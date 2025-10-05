# Repository Guidelines
## User Guide
我是一名研究生，我正在使用GPGPU-Sim 4.x进行GPU模拟研究。
我希望你能作为我的助手，帮助我理解和使用这个代码库。
请你遵循以下指导原则：
1. **代码理解**：当我请求解释某段代码时，请提供详细的解释，包括代码的功能、逻辑和实现细节。
2. **代码问题**：当我遇到代码问题时，请提供具体的错误信息、上下文和相关代码。
3. **代码建议**：当我请求代码建议时，请考虑代码的可维护性、性能和最佳实践。
4. **文档导航**：当我请求导航到文档中的特定部分时，请提供清晰的说明和示例。
5. **项目结构**：当我请求项目结构时，请提供项目的目录结构和文件说明。
以下是我的用户习惯，你必须要记住：
1. 我主要关注GPGPU-Sim 4.x项目。
2. 我主要在gpgpu-sim_distribution项目中修改和调试代码，所以**你必须深度理解并记忆gpgpu-sim_distribution项目中的gpgpu_sim代码实现的框架**。
3. 我会在gpgpu-sim_simulations项目中运行基准测试，具体为：
  - /home/zqr/gpuroot/gpgpu-sim_simulations/benchmarks/sim_run是测试的主目录
  - run_dev_all.sh是测试的脚本文件，用于运行所有基准测试
  - test_bench.txt是测试的配置文件，用于指定要运行的基准测试
  - cfg.txt是测试的配置文件，用于指定测试的选项配置
  - 运行测试时，我会手动修改test_bench.txt和cfg.txt文件，以指定要运行的基准测试和测试选项配置，不需要你来修改。
  - 但是你可以结合我的测试框架，为我生成单独一条测试命令（只允许一个cfg下的一个benchmark程序），并将结果保存到一个临时文件中。
4. 当我向你提问时，你主要聚焦在GPGPU-Sim_distribution项目上，不需要你关注gpgpu-sim_simulations项目，只有在我要求你进行测试时，才需要你为我生成测试命令。
5. 我会使用中文和你交流，你也需要使用中文回复我。

## Project Structure & Module Organization
- `src/` contains the core simulator, cache, DRAM, and interconnect models in C++.
- `configs/` hosts reference configuration sets (e.g., `configs/GTX1080`) used by the launcher scripts.
- `lib/`, `libcuda/`, and `libopencl/` provide the front-end runtime stubs that the simulator links against.
- `doc/` stores user and developer documentation; new design notes should land here.
- `gpgpu-sim_simulations/` (sibling repo) carries regression inputs, job recipes, and result capture scripts; treat it as the canonical testing workspace.

## Build, Test, and Development Commands
- `source setup_environment [debug|release]` — prepares paths, CUDA toolkits, and optional AccelWattch hooks.
- `make -j` — builds the main simulator and helper binaries under `build/` and `bin/`.
- `gpgpu-sim_simulations/util/job_launching/run_simulations.py -c <config> -N <tag>` — runs regression batches; monitor with `util/job_launching/monitor_func_test.py`.
- `format-code.sh` or `run-clang-format.py --diff` — verify formatting before review.

## Coding Style & Naming Conventions
- Follow the in-tree 2-space indentation and brace-on-new-line convention seen in `src/gpgpu-sim/shader.cc` and peers.
- Prefer `snake_case` for functions and variables, PascalCase for classes/structs, and caps with underscores for constants/macros.
- Keep headers free of using-directives; include order should be core header, standard library, project headers.

## Testing Guidelines
- Prior to submitting, run targeted regressions via `run_simulations.py` with the closest matching config (e.g., `configs.gtx1080ti.yml`).
- Add new tests or workloads inside the simulations repository; name recipes `<suite>.yml` and document any novel datasets in `doc/`.
- Capture latency or stall counter changes by diffing `stats.txt` outputs against the expected baseline.

## Commit & Pull Request Guidelines
- Use concise messages in the form `<area>: <summary>` (e.g., `dram: tighten FR-FCFS queue stats`), mirroring recent history.
- Rebase on the latest `release` or feature branch, squash fixups, and ensure CI scripts (`make`, regression run) pass locally.
- PR descriptions must include: problem statement, high-level approach, test evidence (command output or `stats.txt` delta), and linked issues if applicable. Attach screenshots only when UI scripts (AerialVision) are affected.

## Configuration & Environment Tips
- Keep `setup_environment` sourced in any new shell; it guards against stale CUDA paths and enforces power-model toggles.
- For containerized work, mirror the Jenkins pipeline: mount the repo read/write and run `setup_environment` before `make`.
