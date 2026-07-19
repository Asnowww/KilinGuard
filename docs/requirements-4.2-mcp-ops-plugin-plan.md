# 4.2 MCP 运维插件化子系统开发与验收方案

本文对应 `docs/requirements.tex` 第 4.2 节 FR-2.1 至 FR-2.16，目标是在
[ultraworkers/claw-code](https://github.com/ultraworkers/claw-code) 的 Rust 主实现上增量开发，
复用现有 MCP、工具注册、权限检查、插件生命周期和命令执行组件，不另建一套旁路执行框架。

## 1. 总体架构

```text
LLM / CLI
    |
    v
tools::ToolRegistry + PermissionEnforcer
    |
    +-- runtime::McpServerManager ------ stdio / SSE MCP Server
    |
    +-- plugins::PluginRegistry -------- 外部插件 / 内置运维插件
    |       |
    |       +-- 清单、发现、版本、依赖、热加载
    |       +-- JSON Schema、权限声明、进程沙箱
    |
    +-- ops_plugin_sdk::WorkflowRunner - 顺序、并行、管道、检查点、回滚
```

关键原则：

- 所有插件调用最终进入既有 `ToolRegistry`，禁止绕开 `PermissionEnforcer`。
- 内置运维能力也以插件清单和统一 Schema 暴露，避免形成不受生命周期管理的特例。
- 外部进程默认隔离；Linux/麒麟使用 `systemd-run` 用户作用域沙箱，非 Linux 平台无法满足
  隔离策略时拒绝执行。
- 工作流只组合已注册工具，每个嵌套步骤仍独立执行权限校验。
- 所有持久化状态限制在工作区 `.claw/` 下，并拒绝符号链接或 Windows reparse point 路径。

## 2. 需求逐项方案

| 需求 | 开发方案 | 主要复用点 | 验收重点 |
| --- | --- | --- | --- |
| FR-2.1 | 完成 MCP 客户端 Tool、Resource、ResourceTemplate、Prompt 的发现与调用，并把操作期协议快照附加到结果。 | `runtime::mcp_stdio`、`runtime::mcp_tool_bridge`、`tools::ToolRegistry` | 三类能力均可列举和调用；单个服务失败不破坏健康服务。 |
| FR-2.2 | 本地插件走 stdio JSON-RPC；远程插件走 SSE，会话端点由服务端事件确定。两类传输共享能力目录和错误模型。 | `runtime::mcp_client`、`runtime::config`、既有 SSE 解析器 | stdio/SSE 初始化、调用、超时和错误路径均有测试。 |
| FR-2.3 | 按传输策略维护支持版本集合，在 initialize 阶段协商并校验 `protocolVersion`，拒绝畸形或不支持版本。 | MCP initialize 状态机、配置合并与运行时状态报告 | 默认版本、显式首选版本、兼容版本及不支持版本均可预测。 |
| FR-2.4 | 配置操作超时、启动超时、心跳间隔和心跳超时；记录连续失败、最近成功/失败及延迟。 | `McpServerManager`、运行时生命周期报告 | 超时有界；心跳失败进入结构化 degraded 状态且可恢复。 |
| FR-2.5 | 使用声明式 `plugin.json` 描述名称、版本、能力、入口点、权限、Schema、依赖和生命周期钩子。 | `plugins::PluginManifest` 及现有配置加载器 | 缺字段、未知字段、非法命令或非法权限清单 fail closed。 |
| FR-2.6 | 扫描受信插件目录，逐项解析、校验和归一化；坏插件进入 load failure 报告，不阻断其他插件。 | 插件注册表、配置作用域、生命周期报告 | 目录穿越、符号链接、重复插件和不合规清单被拒绝。 |
| FR-2.7 | 使用不可变运行时快照完成热加载；新快照校验成功后原子替换，卸载前执行 shutdown 并停止相关进程。 | `PluginRuntimeManager`、现有 CLI/runtime 状态交接 | 无需重启 Agent；加载失败保留上一健康快照。 |
| FR-2.8 | 安装目录保留多版本，注册表记录激活版本；升级失败按版本策略回滚，清理数量受 `keepVersions` 控制。 | 插件安装注册表和原子文件写入 | 多版本共存、切换、回滚、损坏注册表恢复。 |
| FR-2.9 | 解析依赖版本范围，构建有向图并拓扑排序；拒绝缺失依赖、版本不匹配和依赖环。 | 插件发现结果和 semver 解析 | 加载顺序稳定；依赖错误不启动目标插件。 |
| 内置插件 | 提供 `disk_cleaner`、`service_manager`、`user_manager`、`log_analyzer`、`package_manager`、`firewall_manager`、`cron_manager`、`network_diagnostics`、`backup_manager`。 | 统一运维命令构造、权限分级、审计结果和回滚检查点 | 每个动作支持 inspect/plan；变更动作需授权；确定性变更提供回滚。 |
| FR-2.10 | `ops-plugin-sdk` 提供 Python/Rust 模板、清单、Tool/MCP 入口、契约测试和麒麟说明；`OpsPluginScaffold` 负责生成。 | 现有插件清单与 MCP 数据结构 | 生成产物可校验；Rust 产物需构建后再原子安装二进制。 |
| FR-2.11 | 清单精确声明文件、网络、进程和系统能力；注册时校验声明，运行时按实际工具与命令再次检查。 | `PermissionEnforcer`、工具权限分类、插件审批令牌 | 未声明权限、越界命令和越界路径均被拦截。 |
| FR-2.12 | Tool 输入/输出统一使用 JSON Schema；注册时校验 Schema 自身，调用前校验输入，返回后校验输出。 | `jsonschema`、MCP Tool 元数据、工具桥接层 | 错误包含插件/工具上下文；外部工具必须声明输出 Schema。 |
| FR-2.13 | 外部进程与 Agent 分离；麒麟使用 `systemd-run --user` 配置权限、资源和路径边界；不支持的平台 fail closed。 | 现有无 shell `Command` 执行、进程超时和输出上限 | 禁止 shell 拼接；超时终止；沙箱不可用时不降级裸跑。 |
| FR-2.14 | `WorkflowDefinition` 将连续 parallel 步骤作为并行组，其余按序执行；限制总步骤数和并行宽度。 | `ops_plugin_sdk::WorkflowRunner`、嵌套工具注册 | 并行组全部收敛后进入下一阶段；panic/失败可定位到具体步骤。 |
| FR-2.15 | `inputFrom.stepId/path/targetField` 从已完成步骤选择 JSON 输出并注入下一步骤。 | `serde_json::Value`、Tool JSON 契约 | 禁止未来依赖和同一并行组内依赖；允许引用已收敛的早期并行组。 |
| FR-2.16 | 每个成功步骤持久化版本化检查点；恢复时校验工作流哈希、步骤哈希和进度一致性；逆序执行显式补偿并记录部分失败。 | 原子写文件、SDK observer、插件回滚动作 | 过期、旧格式、伪造跳步/回滚计划和链接路径均拒绝；成功补偿不重复执行，失败补偿可重试。 |

## 3. 内置插件执行策略

所有内置插件返回统一结构：`status`、`mode`、`plan`、`audit`、`error` 和 `rollback`。
建议调用链固定为：

1. `inspect` 获取当前状态和影响范围。
2. `plan` 生成无副作用的命令计划。
3. 权限引擎根据插件、动作、目标和参数进行审批。
4. 使用参数数组直接启动固定绝对路径程序，不经过 shell。
5. 记录退出码、截断标志、变更状态和回滚检查点。
6. 对可确定恢复的动作提供 `rollback`；包管理等无法保证确定恢复的动作明确标记不可逆原因。

麒麟适配命令以 `systemctl`、`journalctl`、`dnf`、`firewall-cmd`、`systemd-run`、
`systemd` timer/service 和标准 `iputils`/DNS 工具为主。运行前必须通过绝对路径白名单及参数校验，
不得把模型输出直接拼接为 shell 命令。

## 4. 工作流与检查点契约

```json
{
  "name": "service-recovery",
  "steps": [
    {
      "id": "inspect",
      "tool": "ops_service_manager",
      "input": {"action": "inspect", "service": "demo.service"}
    },
    {
      "id": "restart",
      "tool": "ops_service_manager",
      "inputFrom": {
        "stepId": "inspect",
        "path": "result",
        "targetField": "previousState"
      },
      "input": {"action": "restart", "service": "demo.service"},
      "rollback": {
        "id": "restore_service_state",
        "tool": "ops_service_manager",
        "input": {"action": "rollback", "checkpointId": "..."}
      }
    }
  ]
}
```

检查点信封包含 `schemaVersion`、工作流哈希、逐步骤哈希、更新时间、过期时间和内部状态。
内部状态记录 `next_index`、完成输出与顺序、失败步骤、逆序回滚计划、回滚结果及显式不可逆步骤。
恢复前重新由当前工作流推导合法进度和回滚计划，禁止信任磁盘中的可执行回滚输入。

## 5. 麒麟与 LoongArch 部署方案

- 构建：在目标麒麟版本上使用稳定 Rust 工具链执行 `cargo build --workspace --release --locked`。
- 架构：优先在 LoongArch 主机原生构建；交叉编译时使用与目标 glibc、OpenSSL 和 systemd
  兼容的 sysroot，并在真机重新执行集成测试。
- 服务：Agent 以普通用户运行；外部插件通过 `systemd-run --user` 创建瞬时作用域，禁止默认 root。
- 目录：插件放入受信目录；检查点位于工作区 `.claw/workflow-checkpoints`；敏感文件使用
  `0600`，新建私有目录使用 `0700`。
- 依赖探测：启动时检查 systemd user manager、`dnf`、`firewall-cmd`、`journalctl` 等；缺失能力
  只禁用对应插件并输出结构化 degraded 报告。
- 发布：产出 x86_64 与 LoongArch64 两套构建及 SHA-256；禁止把 Windows 测试结果作为麒麟验收结论。

## 6. 验收与回归

当前 Windows 开发机复核快照：

- `ops-plugin-sdk`：24/24 通过。
- `tools`：133/133 通过。
- `plugins`：142/142 通过。
- `runtime` MCP 专项：133/133 通过。
- `rusty-claude-cli` 主二进制：221/221 通过。
- `cargo check --workspace --tests --locked` 与 `cargo fmt --all -- --check` 通过。
- `runtime` 全量 660 项中 646 项通过；14 项既有 Windows 钩子脚本/OAuth 临时路径测试失败，
  不属于 MCP/插件改动面，不能据此声称全工作区测试完全通过。

开发机通用门禁：

```bash
cd rust
cargo fmt --all -- --check
cargo test -p ops-plugin-sdk --lib -- --test-threads=1
cargo test -p plugins --lib -- --test-threads=1
cargo test -p runtime mcp --lib -- --test-threads=1
cargo test -p tools --lib -- --test-threads=1
cargo test -p rusty-claude-cli --lib -- --test-threads=1
cargo check --workspace --tests --locked
```

麒麟目标机必须补充：

- stdio 与 SSE 真实 MCP 服务互操作测试。
- 热加载过程中并发调用与失败回退测试。
- 九个内置插件的 inspect/plan/授权执行/拒绝/回滚测试。
- `systemd-run --user` 沙箱属性、超时终止、输出上限和权限越界测试。
- 进程中断后工作流检查点恢复、并行组崩溃窗口、部分回滚重试测试。
- x86_64 与 LoongArch64 构建、启动和基础运维命令测试。

Windows 可验证平台无关逻辑和 fail-closed 分支，但 Linux `cfg` 测试、systemd 沙箱与麒麟命令
必须在目标系统执行后才能签署最终验收。
