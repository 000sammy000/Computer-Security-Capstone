# Makefile

# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -pthread -lnetfilter_queue

# Source files
PHARM_SRCS = pharm_attack.cpp
MITM_SRCS = mitm_attack.cpp

# Object files
PHARM_OBJS = $(PHARM_SRCS:.cpp=.o)
MITM_OBJS = $(MITM_SRCS:.cpp=.o)

# Executable names
PHARM_TARGET = pharm_attack
MITM_TARGET = mitm_attack

# Default rule
all: $(PHARM_TARGET) $(MITM_TARGET)

# Rule to compile .cpp files to .o files for pharm_attack
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to compile .cpp files to .o files for mitm_attack
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to link object files to create the pharm_attack executable
$(PHARM_TARGET): $(PHARM_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Rule to link object files to create the mitm_attack executable
$(MITM_TARGET): $(MITM_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@

# Clean rule
clean:
	rm -f $(PHARM_OBJS) $(MITM_OBJS) $(PHARM_TARGET) $(MITM_TARGET)
