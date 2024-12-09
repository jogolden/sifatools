CXX = clang++
CXXFLAGS = -Wall -Wextra -std=c++20 -O3
LDFLAGS = 

SRC = sifa.cpp
OBJ = $(SRC:.cpp=.o)
BIN = sifa

all: $(BIN)

assembly: $(SRC)
	$(CXX) $(CXXFLAGS) -S -fverbose-asm $< -o $(BIN).s
	@echo "Generated assembly: $(BIN).s"

disasm: $(BIN)
	objdump -d $(BIN) > $(BIN)_disasm.txt
	@echo "Generated disassembly: $(BIN)_disasm.txt"

$(BIN): $(OBJ)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJ) $(BIN) $(BIN).s $(BIN)_disasm.txt

rebuild: clean all

.PHONY: all clean rebuild a
