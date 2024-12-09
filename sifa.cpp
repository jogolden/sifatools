// John Fitzgerald
// MacOS arm specific
// 84 ineffective faults, searches 2^32 in 5 minutes :O
// 2024
//

#include <arm_neon.h>
#include <pthread.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <numeric>
#include <string>
#include <thread>
#include <vector>

constexpr uint64_t TOTAL_KEYS = (1ULL << 32);

bool verbose = false;

// KG0 fault state[0][0], look at state[0][0]
// KG1 fault state[0][3], look at state[1][3]
// KG2 fault state[0][2], look at state[2][2]
// KG3 fault state[0][1], look at state[3][1]
enum keygroup_t {
    KEYGROUP_0 = 0,
    KEYGROUP_1,
    KEYGROUP_2,
    KEYGROUP_3,
    KEYGROUP_UNKNOWN = -1
};

std::mutex result_mutex;
uint64_t best_key = 0;
double max_sei = -std::numeric_limits<double>::infinity();
std::atomic<uint64_t> progress_counter{0};  // Atomic for thread-safe progress tracking

void print_usage(char* argv0) {
    std::cerr << "usage: " << argv0 << " -i [input data] [-o output text] [-v] [-s sample_limit]" << std::endl;
    std::exit(EXIT_FAILURE);
}

// TODO: add error detection to this function
void load_fault_data(char* filename, std::vector<std::vector<uint8_t>>& plaintexts, std::vector<std::vector<uint8_t>>& ciphertexts, uint32_t& ineffective) {
    std::ifstream fp(filename, std::ios::binary);
    if (!fp.is_open()) {
        std::cerr << "failed to open file: " << filename << std::endl;
        std::exit(EXIT_FAILURE);
    }

    // Read ineffective faults count
    fp.read(reinterpret_cast<char*>(&ineffective), sizeof(ineffective));
    if (verbose) {
        std::cout << "loading " << ineffective << " ineffective faults" << std::endl;
    }

    // Read plaintexts and ciphertexts
    for (uint32_t i = 0; i < ineffective; ++i) {
        std::vector<uint8_t> plaintext(16), ciphertext(16);

        fp.read(reinterpret_cast<char*>(plaintext.data()), 16);
        fp.read(reinterpret_cast<char*>(ciphertext.data()), 16);

        plaintexts.push_back(plaintext);
        ciphertexts.push_back(ciphertext);
    }

    fp.close();
}

inline uint8_t partial_decrypt_9(std::vector<uint8_t>& ciphertext, enum keygroup_t kg, uint8_t kg0, uint8_t kg1, uint8_t kg2, uint8_t kg3) {
    // Load ciphertext directly into a NEON register
    uint8x16_t state = vld1q_u8(ciphertext.data());

    // Create the keyguess NEON register
    uint8x16_t keyguess;
    switch (kg) {
        case KEYGROUP_0:
            keyguess = vsetq_lane_u8(kg0, vdupq_n_u8(0), 0);
            keyguess = vsetq_lane_u8(kg1, keyguess, 7);
            keyguess = vsetq_lane_u8(kg2, keyguess, 10);
            keyguess = vsetq_lane_u8(kg3, keyguess, 13);
            break;
        case KEYGROUP_1:
            keyguess = vsetq_lane_u8(kg0, vdupq_n_u8(0), 1);
            keyguess = vsetq_lane_u8(kg1, keyguess, 4);
            keyguess = vsetq_lane_u8(kg2, keyguess, 11);
            keyguess = vsetq_lane_u8(kg3, keyguess, 14);
            break;
        case KEYGROUP_2:
            keyguess = vsetq_lane_u8(kg0, vdupq_n_u8(0), 2);
            keyguess = vsetq_lane_u8(kg1, keyguess, 5);
            keyguess = vsetq_lane_u8(kg2, keyguess, 8);
            keyguess = vsetq_lane_u8(kg3, keyguess, 15);
            break;
        case KEYGROUP_3:
            keyguess = vsetq_lane_u8(kg0, vdupq_n_u8(0), 3);
            keyguess = vsetq_lane_u8(kg1, keyguess, 6);
            keyguess = vsetq_lane_u8(kg2, keyguess, 9);
            keyguess = vsetq_lane_u8(kg3, keyguess, 12);
            break;
        default:
            throw std::runtime_error("invalid key group");
            break;
    }

    // Inverse ShiftRows, SubBytes, and MixColumns using AES decryption round
    state = vaesdq_u8(state, keyguess);
    state = vaesimcq_u8(state);

    switch (kg) {
        case KEYGROUP_0:
            return vgetq_lane_u8(state, 0);
            break;
        case KEYGROUP_1:
            return vgetq_lane_u8(state, 7);
            break;
        case KEYGROUP_2:
            return vgetq_lane_u8(state, 10);
            break;
        case KEYGROUP_3:
            return vgetq_lane_u8(state, 13);
            break;
        default:
            throw std::runtime_error("invalid key group");
            break;
    }
}

inline double compute_sei(std::array<int, 256>& counts) {
    double total = std::accumulate(counts.begin(), counts.end(), 0.0);
    constexpr double expected = 1.0 / 256.0;  // uniform distribution
    double sei = 0.0;

    for (int count : counts) {
        double p = count / total;
        sei += std::pow(p - expected, 2);
    }

    return sei;
}

void set_high_priority() {
    pthread_t this_thread = pthread_self();

    struct sched_param params;
    params.sched_priority = sched_get_priority_max(SCHED_FIFO);

    if (pthread_setschedparam(this_thread, SCHED_FIFO, &params) != 0) {
        std::cerr << "failed to set thread priority" << std::endl;
    }
}

void search_keyspace(uint32_t ineffective, keygroup_t keygroup, uint64_t start, uint64_t end, std::vector<std::vector<uint8_t>>& ciphertexts) {
    double local_max_sei = -std::numeric_limits<double>::infinity();
    uint64_t local_best_key = 0;

    set_high_priority();

    // Preallocate counts outside the loop
    std::array<int, 256> counts;

    for (uint64_t keyguess = start; keyguess < end; ++keyguess) {
        uint8_t kg0 = keyguess & 0xFF;
        uint8_t kg1 = (keyguess >> 8) & 0xFF;
        uint8_t kg2 = (keyguess >> 16) & 0xFF;
        uint8_t kg3 = (keyguess >> 24) & 0xFF;

        // Zero the counts array efficiently
        counts.fill(0);

        // Perform decryption and count results
        for (size_t i = 0; i < ineffective; ++i) {
            uint8_t result = partial_decrypt_9(ciphertexts[i], keygroup, kg0, kg1, kg2, kg3);
            counts[result]++;
        }

        // Compute Squared Euclidean Imbalance
        // My best frieend <3
        double sei_score = compute_sei(counts);
        if (sei_score > local_max_sei) {
            local_max_sei = sei_score;
            local_best_key = keyguess;
        }

        // Update progress safely
        progress_counter++;
    }

    // Update global best score using a mutex
    std::lock_guard<std::mutex> lock(result_mutex);
    if (local_max_sei > max_sei) {
        max_sei = local_max_sei;
        best_key = local_best_key;
    }
}

void write_output(std::ostream& out, uint32_t ineffective, keygroup_t kg, long elapsed) {
    out << std::dec << ineffective << " ineffective faults" << std::endl;
    out << "keygroup: " << std::dec << kg << std::endl;

    uint8_t kg0 = best_key & 0xFF;
    uint8_t kg1 = (best_key >> 8) & 0xFF;
    uint8_t kg2 = (best_key >> 16) & 0xFF;
    uint8_t kg3 = (best_key >> 24) & 0xFF;

    out << std::hex << std::setfill('0');

    switch (kg) {
        case KEYGROUP_0:
            out << "key byte 0: 0x" << std::setw(2) << static_cast<int>(kg0) << std::endl;
            out << "key byte 7: 0x" << std::setw(2) << static_cast<int>(kg1) << std::endl;
            out << "key byte 10: 0x" << std::setw(2) << static_cast<int>(kg2) << std::endl;
            out << "key byte 13: 0x" << std::setw(2) << static_cast<int>(kg3) << std::endl;
            break;
        case KEYGROUP_1:
            out << "key byte 1: 0x" << std::setw(2) << static_cast<int>(kg0) << std::endl;
            out << "key byte 4: 0x" << std::setw(2) << static_cast<int>(kg1) << std::endl;
            out << "key byte 11: 0x" << std::setw(2) << static_cast<int>(kg2) << std::endl;
            out << "key byte 14: 0x" << std::setw(2) << static_cast<int>(kg3) << std::endl;
            break;
        case KEYGROUP_2:
            out << "key byte 2: 0x" << std::setw(2) << static_cast<int>(kg0) << std::endl;
            out << "key byte 5: 0x" << std::setw(2) << static_cast<int>(kg1) << std::endl;
            out << "key byte 8: 0x" << std::setw(2) << static_cast<int>(kg2) << std::endl;
            out << "key byte 15: 0x" << std::setw(2) << static_cast<int>(kg3) << std::endl;
            break;
        case KEYGROUP_3:
            out << "key byte 3: 0x" << std::setw(2) << static_cast<int>(kg0) << std::endl;
            out << "key byte 6: 0x" << std::setw(2) << static_cast<int>(kg1) << std::endl;
            out << "key byte 9: 0x" << std::setw(2) << static_cast<int>(kg2) << std::endl;
            out << "key byte 12: 0x" << std::setw(2) << static_cast<int>(kg3) << std::endl;
            break;
        default:
            throw std::runtime_error("invalid key group");
    }

    out << "max SEI: " << std::dec << max_sei << std::endl;
    out << "elapsed time: " << elapsed << " seconds" << std::endl;
}

void file_write_output(const std::string& output_file, uint32_t ineffective, keygroup_t kg, long elapsed) {
    std::ofstream out_file(output_file, std::ios::out | std::ios::app);  // Append mode

    if (!out_file.is_open()) {
        std::cerr << "failed to open output file: " << output_file << std::endl;
        return;
    }

    write_output(out_file, ineffective, kg, elapsed);

    out_file.close();
}

int main(int argc, char* argv[]) {
    int opt;
    char* input_file = NULL;
    char* output_file = NULL;
    keygroup_t keygroup = KEYGROUP_0;
    uint32_t sample_limit = 0;  // Default: no limit

    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "i:o:s:k:v")) != -1) {
        switch (opt) {
            case 'i':
                input_file = optarg;
                break;
            case 'o':
                output_file = optarg;
                break;
            case 's': {
                char* endptr;
                sample_limit = std::strtoul(optarg, &endptr, 10);
                if (*endptr != '\0' || sample_limit == 0) {
                    std::cerr << "Invalid sample limit: " << optarg << std::endl;
                    print_usage(argv[0]);
                }
                break;
            }
            case 'k': {
                int kg = std::atoi(optarg);
                if (kg >= 0 && kg <= 3) {
                    keygroup = static_cast<keygroup_t>(kg);
                } else {
                    std::cerr << "invalid keygroup: " << kg << std::endl;
                    print_usage(argv[0]);
                }
                break;
            }
            case 'v':
                verbose = true;
                break;
            default:
                print_usage(argv[0]);
        }
    }

    // Ensure mandatory arguments are provided
    if (!input_file) {
        print_usage(argv[0]);
    }

    if (verbose) {
        std::cout << "verbose mode" << std::endl;
        std::cout << "keygroup: " << std::dec << keygroup << std::endl;
    }

    std::vector<std::vector<uint8_t>> plaintexts, ciphertexts;
    uint32_t ineffective = 0;

    load_fault_data(input_file, plaintexts, ciphertexts, ineffective);

    if (sample_limit != 0) {
        if (ineffective < sample_limit) {
            std::cout << "warning: supplied sample limit is greater than number of ineffective faults" << std::endl;
        } else {
            if (verbose) {
                std::cout << "sample limit: " << std::dec << sample_limit << std::endl;
            }
            ineffective = sample_limit;
        }
    }

    const unsigned num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;
    uint64_t keys_per_thread = TOTAL_KEYS / num_threads;

    auto start_time = std::chrono::high_resolution_clock::now();

    // Launch threads
    for (unsigned t = 0; t < num_threads; t++) {
        uint64_t start = t * keys_per_thread;
        uint64_t end = (t == num_threads - 1) ? TOTAL_KEYS : start + keys_per_thread;
        threads.emplace_back(search_keyspace, ineffective, keygroup, start, end, std::ref(ciphertexts));
    }

    // Monitor progress
    uint64_t last_percent = 0;
    while (progress_counter < TOTAL_KEYS) {
        uint64_t percent_done = (progress_counter * 100) / TOTAL_KEYS;
        if (percent_done != last_percent) {
            last_percent = percent_done;

            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();

            std::cout << "progress: " << percent_done << "% completed. elapsed time: " << elapsed << " seconds.\r" << std::flush;
        }
    }

    // Wait for all threads to complete
    for (auto& th : threads) {
        th.join();
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(end_time - start_time).count();

    write_output(std::cout, ineffective, keygroup, elapsed);

    // Write output to file
    if (output_file) {
        file_write_output(output_file, ineffective, keygroup, elapsed);
    }

    return 0;
}
