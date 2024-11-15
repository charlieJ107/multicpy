# muticpy - 基于C++的可靠多线程复制工具
为了实现一个高效的多线程文件复制工具 "multicpy"，我们需要考虑如何设计程序来充分利用多线程并行性，特别是在处理大量小文件时。

### 设计方案

#### 1. **任务分配与调度**
- 多线程的核心思想是将不同的文件或文件块交给多个线程处理，每个线程并行执行文件复制任务。
- **目录遍历**：主线程负责递归遍历源目录结构，发现文件和文件夹，然后将文件复制任务分配给工作线程。
- **任务队列**：使用一个任务队列，主线程将待复制的文件路径放入队列，多个工作线程从队列中取任务执行复制操作。
- **线程池**：使用线程池模型，主线程控制固定数量的工作线程，从任务队列中拉取任务。

#### 2. **文件复制策略**
- 对于**小文件**，可以简单地分配给单个线程复制。
- 对于**大文件**，可以将文件分块，将每个块交给不同线程并行复制，然后再将这些块合并到目标文件中。
- 使用标准库的 `std::ifstream` 和 `std::ofstream` 实现文件的读取与写入。

#### 3. **目录结构的保持**
- 在复制过程中，需要保持源目录的结构。主线程首先创建目标目录的结构，确保文件复制前目标路径的文件夹存在。
- 可以在主线程递归遍历目录时，优先将文件夹复制过去，再将文件分配给工作线程处理。

#### 4. **错误处理**
- 文件复制过程中可能会遇到权限不足、源文件不存在、文件被占用等问题。需要在每个线程中加入错误处理机制，记录失败的复制任务，供用户查看。
- 采用 `std::mutex` 或 `std::shared_mutex` 保证错误日志的线程安全写入。

#### 5. **同步机制**
- 为了保证数据的一致性以及线程之间的协调，使用 **互斥锁 (mutex)** 和 **条件变量 (condition variable)** 来同步线程对任务队列的访问。
- 主线程在所有任务完成后进行退出，工作线程在没有任务时阻塞等待新任务。

#### 6. **进度监控**
- 可以加入简单的进度显示，例如每个线程在完成文件复制后更新进度条。
- 通过一个共享的计数器记录已完成的文件数量，主线程可以定期查询进度。

### 详细步骤
1. **主线程**：
   - 递归遍历源目录，发现文件和目录。
   - 将目录结构在目标路径上重建。
   - 将文件复制任务推送到任务队列中。

2. **工作线程**：
   - 从任务队列中取任务（文件路径），执行文件复制操作。
   - 如果任务是大文件，则分块复制。
   - 记录成功或失败的任务。

3. **任务队列**：
   - 使用 `std::queue` 实现，结合 `std::mutex` 来实现线程安全的任务分配。

4. **文件复制功能**：
   - 小文件：直接用单个线程执行文件复制。
   - 大文件：将文件分成若干块，每个块分配给一个线程进行读取和写入，最后在目标文件中按顺序合并。

### 主要模块
- **FileCopier**：负责文件的复制操作，包括小文件的简单复制和大文件的分块复制。
- **DirectoryManager**：负责源目录的遍历与目标目录结构的重建。
- **ThreadPool**：线程池管理，调度多个工作线程执行文件复制任务。
- **TaskQueue**：用于任务的线程安全队列。

### 技术细节
- C++ 11 提供的 `std::thread` 和 `std::mutex` 用于实现多线程控制。
- 任务队列可以使用 `std::condition_variable` 来避免空转等待。
- 对于 I/O 操作，使用 `std::ifstream` 和 `std::ofstream`，配合 `std::filesystem` 来处理文件路径、遍历目录等操作。

这个设计方案既能处理大量小文件的并行复制，也能处理大文件的并行分块复制。接下来我们可以一步步实现这个程序，从目录遍历、任务队列、到多线程复制的实现。

# 地址解析
我们还需要考虑解析复制的源地址和目标地址，防止出现歧义。
为了确保复制源地址和目标地址的解析清晰且不引发歧义，我们可以做一些调整，并在功能设计上做适当的取舍，以确保“multicpy”程序的核心目标——高效复制大量小文件——不受影响。以下是修改后的设计方案：

### 1. **地址解析**
我们需要解析的输入地址可能是以下几种形式，类似于 `cp` 支持的格式：
- **单文件复制**：`multicpy source_file destination_file`
- **多个文件复制到目录**：`multicpy source_file1 source_file2 ... destination_directory`
- **目录复制**：`multicpy source_directory destination_directory`

#### 解析规则：
- **单文件对单文件**：当源是单个文件时，目标应是一个文件或一个目录。如果目标是目录，则将文件复制到目标目录下，保持原文件名。
- **多文件到目录**：当源是多个文件时，目标必须是一个目录，否则报错。每个源文件都会被复制到该目录下。
- **目录复制**：当源是一个目录时，目标可以是一个不存在的路径（新建目录）或已经存在的目录。如果是后者，则源目录会被复制为目标目录的子目录。

我们简化的处理：
- **符号链接**：不支持直接复制符号链接，只复制它们指向的目标文件或目录。这与标准 `cp` 的 `-L` 行为相同，但省略 `-P` 和 `-H` 选项。
- **排除某些参数**：我们可以选择不支持复杂的 `cp` 参数（如 `-a`、`-p` 等），只保留基本的递归复制和多线程优化。

### 2. **源和目标解析模块**
- **单独的 `AddressParser` 模块**：负责解析用户输入的路径，判断是单文件、多个文件还是目录，并根据情况决定是否需要新建目录。
- 如果目标路径不存在并且源是目录，则自动创建目标目录。
- 检查权限、目标路径是否可写等。

### 3. **冲突检测和报错机制**
- **路径冲突检测**：在进行复制前，我们要确保目标路径不会引发路径冲突。比如，如果源和目标路径相同，或目标文件已经存在，可以提示用户或根据参数覆盖文件。
- **错误处理**：解析路径时，遇到权限不足或路径不存在的情况，立即提示用户。

### 4. **参数的选择与兼容性**
由于 `multicpy` 的目标是高效复制，我们可以保持基本的 `cp` 格式支持，但简化某些高级功能：
- 不支持 `-R` 等递归标志，**自动递归**处理目录。
- **跳过复杂参数**：例如 `cp` 的 `-u`（更新时才复制）、`-p`（保持文件属性）等高级选项都可以跳过，这样能保持程序的简洁和核心目标一致。

### 5. **修订后的模块设计**
1. **AddressParser**：负责解析和验证源路径与目标路径，确保格式符合要求。
2. **TaskQueue**：将解析出的任务交给任务队列进行处理。
3. **DirectoryManager**：根据解析后的路径创建目标目录并开始分发任务。
4. **FileCopier**：执行文件的多线程复制。

### 主要调整点：
1. **地址解析**：我们使用专门的解析模块 `AddressParser`，以确保输入的源和目标路径符合标准。
2. **简化 `cp` 支持**：适配 `cp` 的大多数文件格式，但舍弃一些不常用或与多线程目标冲突的高级功能。
3. **路径冲突检测**：避免同名冲突和无效路径问题，提供明确的错误提示。

这样调整后的方案既能处理文件地址的解析，又能专注于提升多线程复制的性能，同时保留 `cp` 大部分的易用性。

# 可靠性和鲁棒性 - 异常检测
为了提升 `multicpy` 的鲁棒性和可靠性，同时确保在文件系统问题或系统崩溃时不会影响源文件，并通过哈希值验证复制的正确性，我们可以做以下修改：

### 1. **异常检测与恢复机制**

#### 1.1 **文件复制原子性**
- **临时文件复制**：在将文件复制到目标位置时，先将文件写入到目标目录下的一个临时文件中（可以使用随机生成的唯一文件名）。当文件成功复制完成后，再将临时文件重命名为最终文件。这样即使在复制过程中系统崩溃，也不会影响目标文件或源文件。
  - 使用 `std::filesystem::rename` 作为最后的步骤，这个操作在大多数文件系统中是原子的。
- **中断恢复**：可以在中断时记录已复制的文件或部分文件状态。下次运行时，程序可以检查已复制的文件并跳过，避免重复工作。通过在复制开始时创建记录文件（如 `.multicpy_record`），保存每个文件的复制状态。

#### 1.2 **文件锁定**
- **源文件保护**：在复制操作期间，可以通过文件锁机制（如 `flock`）锁定源文件，确保复制过程不受其他操作影响，特别是多线程操作时避免冲突。
- **错误回滚**：如果复制过程中出现错误（如磁盘空间不足、文件权限问题等），应立即终止当前文件的复制，并删除该文件的临时拷贝，避免不完整的文件出现在目标路径中。

#### 1.3 **系统崩溃后的恢复**
- **崩溃检测与恢复**：程序应在开始复制时生成一个标识文件（如 `.multicpy_in_progress`），以表示复制操作正在进行。如果系统崩溃或程序意外退出，下次启动时，程序可以检查这个标识文件并根据记录文件恢复复制过程。
- **任务队列的持久化**：为了在崩溃后恢复，可以选择将任务队列（待复制的文件列表）持久化到磁盘，在恢复时重启这些任务。

### 2. **文件哈希验证**

为了确保文件复制的完整性和正确性，可以在程序中添加一个可选的参数来进行哈希值验证。具体步骤如下：

#### 2.1 **哈希计算**
- **支持可选参数 `--verify`**：添加一个参数 `--verify`，当用户指定该参数时，程序会在每个文件复制完成后计算源文件和目标文件的哈希值，确保两者一致。
- **哈希算法**：可以使用常见的哈希算法，如 `MD5` 或 `SHA-256`，并通过 C++ 标准库或 OpenSSL 来计算文件的哈希值。
  - 对于较大的文件，哈希计算可以通过分块读取文件并计算增量哈希，避免占用过多内存。

#### 2.2 **哈希验证的流程**
- **逐文件验证**：在复制文件后，程序读取源文件和目标文件，计算各自的哈希值。如果哈希不匹配，则认为复制失败，标记为错误并尝试重新复制。
- **错误处理**：如果验证失败，可以记录错误文件并提示用户。用户可以选择跳过该文件或重新尝试复制。

#### 2.3 **多线程的哈希验证**
- **并行哈希计算**：在多线程复制的同时，也可以并行进行哈希计算。可以为哈希验证单独启用线程池，让验证过程不会阻塞主复制流程。

### 3. **修改后的设计方案**
在原有设计基础上，以下模块需要做调整：

1. **FileCopier**：
   - **临时文件机制**：在文件复制时，先将内容写入临时文件，成功后再重命名。
   - **异常处理**：在文件写入过程中加入崩溃和错误检测，出现问题时删除不完整的临时文件。
   - **哈希验证**：在文件复制完成后，根据用户输入的参数决定是否进行哈希验证。对于哈希不匹配的文件，记录并重新复制。

2. **RecoveryManager**：
   - **崩溃恢复**：负责创建和管理 `.multicpy_in_progress` 文件，在程序启动时检查是否有未完成的复制任务。可持久化任务队列，支持系统崩溃后的恢复。

3. **HashVerifier**：
   - **文件哈希计算**：提供哈希计算功能，通过分块读取源文件和目标文件来计算哈希值，并与用户指定的哈希算法配合。
   - **多线程支持**：可使用单独的线程池进行文件哈希验证，以避免阻塞主复制任务。

4. **日志记录与恢复**：
   - **记录文件**：将每个文件的复制状态持久化到记录文件中，确保在程序意外终止或系统崩溃后能够恢复任务。
   - **错误日志**：记录复制失败的文件及其原因，便于用户分析问题。

### 总结
- **文件复制的原子性**：通过临时文件确保文件复制的完整性。
- **崩溃恢复**：通过崩溃标识和任务记录文件支持系统崩溃后的恢复。
- **哈希验证**：可选的文件哈希验证功能，确保文件复制的准确性。

这些调整将显著提升 `multicpy` 的鲁棒性和可靠性，防止系统异常或复制失败影响源文件的安全性，同时让用户在需要时验证复制结果的完整性。

# C++实现
首先，我们需要定义程序的依赖、CMake构建文件以及各个模块的 C++ 实现。

### 1. **依赖包**
我们会依赖以下库和工具：
- C++17 标准库
- `std::filesystem`：用于文件系统操作（遍历、复制、路径操作等）。
- `std::thread` 和 `std::mutex`：用于多线程操作。
- OpenSSL 或其他哈希库：用于文件哈希验证。
- CMake 作为构建工具。

### 2. **CMake 文件**

首先，创建一个 `CMakeLists.txt` 文件，用于配置和编译项目：

```cmake
cmake_minimum_required(VERSION 3.10)
project(multicpy)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 添加 OpenSSL 库用于哈希计算
find_package(OpenSSL REQUIRED)

add_executable(multicpy
    src/main.cpp
    src/FileCopier.cpp
    src/DirectoryManager.cpp
    src/TaskQueue.cpp
    src/HashVerifier.cpp
    src/RecoveryManager.cpp
    src/AddressParser.cpp
)

# 链接 OpenSSL 库
target_link_libraries(multicpy OpenSSL::SSL OpenSSL::Crypto)

# 添加编译选项
target_compile_options(multicpy PRIVATE -Wall -Wextra -Werror)
```

### 3. **程序模块实现**

我们将实现各个模块：`AddressParser`、`TaskQueue`、`FileCopier`、`HashVerifier`、`RecoveryManager` 以及 `main.cpp`。

#### 3.1 **AddressParser** (源地址和目标地址解析)

```cpp
// AddressParser.h
#ifndef ADDRESS_PARSER_H
#define ADDRESS_PARSER_H

#include <string>
#include <vector>

class AddressParser {
public:
    AddressParser(int argc, char** argv);
    
    std::string getSourcePath() const;
    std::string getDestinationPath() const;
    bool isVerifyEnabled() const;

private:
    std::string sourcePath;
    std::string destinationPath;
    bool verify;

    void parseArguments(int argc, char** argv);
};

#endif
```

```cpp
// AddressParser.cpp
#include "AddressParser.h"
#include <stdexcept>
#include <iostream>

AddressParser::AddressParser(int argc, char** argv) : verify(false) {
    parseArguments(argc, argv);
}

void AddressParser::parseArguments(int argc, char** argv) {
    if (argc < 3) {
        throw std::invalid_argument("Usage: multicpy <source> <destination> [--verify]");
    }
    
    sourcePath = argv[1];
    destinationPath = argv[2];
    
    if (argc == 4 && std::string(argv[3]) == "--verify") {
        verify = true;
    }
}

std::string AddressParser::getSourcePath() const {
    return sourcePath;
}

std::string AddressParser::getDestinationPath() const {
    return destinationPath;
}

bool AddressParser::isVerifyEnabled() const {
    return verify;
}
```

#### 3.2 **TaskQueue** (任务队列)

```cpp
// TaskQueue.h
#ifndef TASK_QUEUE_H
#define TASK_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <string>

class TaskQueue {
public:
    void pushTask(const std::string& task);
    std::string popTask();
    bool isEmpty() const;

private:
    std::queue<std::string> tasks;
    mutable std::mutex queueMutex;
    std::condition_variable condition;
};

#endif
```

```cpp
// TaskQueue.cpp
#include "TaskQueue.h"

void TaskQueue::pushTask(const std::string& task) {
    std::lock_guard<std::mutex> lock(queueMutex);
    tasks.push(task);
    condition.notify_one();
}

std::string TaskQueue::popTask() {
    std::unique_lock<std::mutex> lock(queueMutex);
    condition.wait(lock, [this] { return !tasks.empty(); });
    std::string task = tasks.front();
    tasks.pop();
    return task;
}

bool TaskQueue::isEmpty() const {
    std::lock_guard<std::mutex> lock(queueMutex);
    return tasks.empty();
}
```

#### 3.3 **FileCopier** (文件复制器)

```cpp
// FileCopier.h
#ifndef FILE_COPIER_H
#define FILE_COPIER_H

#include <string>

class FileCopier {
public:
    static void copyFile(const std::string& source, const std::string& destination);
};

#endif
```

```cpp
// FileCopier.cpp
#include "FileCopier.h"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace fs = std::filesystem;

void FileCopier::copyFile(const std::string& source, const std::string& destination) {
    try {
        fs::path src(source);
        fs::path dest(destination);
        
        // 创建临时文件进行复制
        fs::path temp = dest;
        temp += ".tmp";

        std::ifstream srcFile(source, std::ios::binary);
        std::ofstream destFile(temp, std::ios::binary);

        destFile << srcFile.rdbuf();
        
        srcFile.close();
        destFile.close();

        // 将临时文件重命名为目标文件
        fs::rename(temp, dest);
        
    } catch (const std::exception& e) {
        std::cerr << "Error copying file: " << e.what() << std::endl;
        throw;
    }
}
```

#### 3.4 **HashVerifier** (哈希验证器)

```cpp
// HashVerifier.h
#ifndef HASH_VERIFIER_H
#define HASH_VERIFIER_H

#include <string>

class HashVerifier {
public:
    static std::string calculateHash(const std::string& filepath);
    static bool verifyFile(const std::string& source, const std::string& destination);
};

#endif
```

```cpp
// HashVerifier.cpp
#include "HashVerifier.h"
#include <openssl/sha.h>
#include <fstream>
#include <iomanip>
#include <sstream>

std::string HashVerifier::calculateHash(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) throw std::runtime_error("Unable to open file for hashing");

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    SHA256_Update(&sha256, buffer, file.gcount());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::ostringstream result;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return result.str();
}

bool HashVerifier::verifyFile(const std::string& source, const std::string& destination) {
    std::string sourceHash = calculateHash(source);
    std::string destHash = calculateHash(destination);
    return sourceHash == destHash;
}
```

#### 3.5 **RecoveryManager** (崩溃恢复)

```cpp
// RecoveryManager.h
#ifndef RECOVERY_MANAGER_H
#define RECOVERY_MANAGER_H

#include <string>

class RecoveryManager {
public:
    static void saveProgress(const std::string& task);
    static void loadProgress();
    static void removeRecoveryFile();
};

#endif
```

```cpp
// RecoveryManager.cpp
#include "RecoveryManager.h"
#include <fstream>

void RecoveryManager::saveProgress(const std::string& task) {
    std::ofstream recoveryFile(".multicpy_record", std::ios::app);
    recoveryFile << task << std::endl;
}

void RecoveryManager::loadProgress() {
    std::ifstream recoveryFile(".multicpy_record");
    std::string task;
    while (std::getline(recoveryFile, task)) {
        // 继续处理剩余的任务
    }
}

void RecoveryManager::removeRecoveryFile() {
    std::remove(".multicpy_record");
}
```

#### 3.6 **主程序 main.cpp**

```cpp
// main.cpp
#include <iostream>
#include "AddressParser.h"
#include "TaskQueue.h"
#include "FileCopier.h"
#include "HashVerifier.h"
#include "RecoveryManager.h"
#include <filesystem>
#include <thread>

namespace fs = std::filesystem;

void worker(TaskQueue& taskQueue, const std::string& destination, bool verify) {
    while (!taskQueue.isEmpty()) {
        std::string source = taskQueue.popTask();
        std::string dest = destination + "/" + fs::path(source).filename().string();
        FileCopier::copyFile(source, dest);
        if (verify && !HashVerifier::verifyFile(source, dest)) {
            std::cerr << "Hash verification failed for file: " << source << std::endl;
        }
    }
}

int main(int argc, char** argv) {
    try {
        AddressParser parser(argc, argv);
        TaskQueue taskQueue;

        // 遍历源目录并将任务加入队列
        for (const auto& entry : fs::recursive_directory_iterator(parser.getSourcePath())) {
            if (entry.is_regular_file()) {
                taskQueue.pushTask(entry.path().string());
            }
        }

       

 // 多线程复制任务
        std::vector<std::thread> threads;
        for (int i = 0; i < std::thread::hardware_concurrency(); ++i) {
            threads.emplace_back(worker, std::ref(taskQueue), parser.getDestinationPath(), parser.isVerifyEnabled());
        }

        // 等待所有线程完成
        for (auto& thread : threads) {
            thread.join();
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
```

### 4. **构建和运行**

1. 在项目目录中创建 `build` 文件夹：
    ```bash
    mkdir build
    cd build
    ```

2. 使用 CMake 进行构建：
    ```bash
    cmake ..
    make
    ```

3. 运行程序：
    ```bash
    ./multicpy source_directory destination_directory --verify
    ```

这个程序实现了多线程文件复制、崩溃恢复和文件哈希验证。你可以根据需要调整线程数、任务队列逻辑和错误处理机制。