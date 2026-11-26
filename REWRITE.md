# 重写计划

- 形态：兼容重实现。交付物是纯 Rust 源码和一个 Rust 二进制。进程里没有 JVM、没有 JRuby、没有 Ruby 解释器，也不去调用 `java`。
- 主案例：Rspack。
- 当前切片：第 5 到第 8 片已通过。波 A 到波 C 已通过（波 B 里除 grok 以外的过滤器仍是各自 gem 的一部分选项）。波 D 已通过。波 E 的持久队列和死信队列已接到管道上，限制写在波 E。波 F 的 elasticsearch、kafka 和 jdbc 的已实现部分已接上，限制写在波 F。波 G 的监控 API 和 `pipeline` 输入输出已接上，限制写在有意差异和波 G。波 H 的 `plugin list` 已接上，keystore 的 PKCS12 文件还没读写。热加载只拒绝 `config.reload.automatic: true`，没有监视器。x-pack 还没做。不要重写事件模型、LSCL 编译器，也不要重写已经能跑的内存管道。
- 上一片：第 2 到第 4 片一起验收。命令 `cargo test` 覆盖 event_fields、parse_sections、conditions、compile_graph。日期 2026-11-25。后又加了 `cargo test --test official`。
- 官方测试：发行包里没有 JUnit / RSpec。源在 `elastic/logstash` tag `v9.5.2`，本机副本在 `target/upstream/logstash`（已 gitignore）。这些测试构造的是 `org.logstash.Event` 和 JRuby，不能直接对 `rstash` 执行。对照方式是把同一批配置和断言喂给 Rust，编译期望值由 9.5.2 的 `compile_imperative` 打到 `tests/fixtures/oracle/official_compiler.txt`。
- `compiler_spec.rb` 和 `config_ast_spec.rb` 里能落到 LSCL 的配置共 83 条，期望值是 9.5.2 `compile_imperative` 的图文本。另外按原断言核对了语句上的 source 协议、id、行号、列号和插件原文，`config.support_escapes` 打开时参数值是处理后的字符串。`010` 按 Ruby `Integer()` 是八进制 8。
- 事件、字段、sprintf 的官方断言已改写成 `cargo test --test official_suite`。覆盖 `EventTest`、`event_spec.rb`、`FieldReferenceTest`、`StringInterpolationTest`、`string_escape_spec.rb` 里的可观察行为：`toJson` / `fromJson`、数组下标（含负数）、`tag`、`append`、`toString`、字段转义 `none` / `percent` / `ampersand`、`%{{YYYY-DDD}}`、`%{{YYYY-'W'ww}}`、`%{+%ss}`。
- `ConfigCompilerTest`：空源和整段注释不产生插件，多段配置按顺序合并，`originalSource` 用换行拼起来。原文非空白时 `uniqueHash` 是这段原文的 SHA-256；原文缺失或只有空白时，用 `Graph#uniqueHash`：各插件和 if 的 `id|protocol|line|column|text` 先各自 SHA-256，排序拼接后再 SHA-256，queue 和 separator 不参与。`complex.cfg` 和 `spec/support/lscl_configs` 下 6 个文件能编过。`PipelineIR` 在 input 和 filter 之间放一个 queue，queue 后面不再有第二个 queue。
- 第 5 到第 8 片的官方插件测例在 `cargo test --test official_plugins --test mutate_spec`。来源是发行包里的 gem：`logstash-codec-plain` 3.1.0、`logstash-codec-line` 3.1.1、`logstash-filter-drop` 3.0.5、`logstash-input-generator` 3.1.0、`logstash-output-stdout` 3.1.4、`logstash-filter-mutate` 3.6.0 的 `spec/filters/mutate_spec.rb` 和 `spec/filters/integration/multi_stage_spec.rb`。`mutate_spec.rs` 里 “convert makes type conversions” 的 85 条样本、gsub / merge 变体、布尔和 float / float_eu 上下文、copy 独立性都按原断言写了。超过 `i128` 的整数（39 位那个）按原数字的十进制文本比较，存在 `Decimal` 里。另外只转了这三处核心测例：`java_pipeline_spec.rb` 里取消的事件不到输出、`runner_spec.rb` 的 `--config.test_and_exit` 和 `-w`、`multi_local_spec.rb` 的 `pipelines.yml`。Java 的 `java_plain` / `java_line` / `java_stdout` 是另一套插件名，不是 `plain` / `line` / `stdout`。`java_pipeline_spec.rb` 和 `runner_spec.rb` 里持久队列、死信队列、指标、API、日志级别没有转，那些属于后面的波次。
- 不在前四片里、因此没有跑：CBOR 字节、JRuby 代理对象身份、`estimateMemory`、Ruby `NoMethodError`、`CompiledPipelineTest`、`EventConditionTest`。字段引用缓存上限、内存里的精确小数、`from_json` 工厂闭包、没有原文时的 `Graph#uniqueHash` 已在 `a1a712d` 按原效果补上。
- 运行时只有 Rust，不嵌入 Java / Ruby，Cargo 只用纯 Rust crate。做不到时停下来问，不要为了编译去链 C 或启动 JVM。
- 预言机：Logstash 9.5.2。发行包 JDK 是 Linux，在 WSL 里跑。管道输出在 `tests/fixtures/oracle/event_fields.out`，直接调用 `org.logstash.Event` / `Timestamp` 的输出在 `tests/fixtures/oracle/event_probe.out`。LSCL 编译结果在 `tests/fixtures/oracle/lscl_compile.txt`，由发行包里的 JRuby 调用 `LogStash::Compiler.compile_imperative` 打出来。命令写在这些文件头上。
- 下一位只做本文件切片表里的下一片。不要从已经通过的切片重新翻译。

进度回复固定包含：当前切片、验收命令、通过还是失败、下一块是什么。

Logstash 9.5.2 是一个常驻进程：读 pipeline 配置，输入插件写事件，队列攒批，过滤插件按顺序改事件，输出插件把事件送走。人通过 `bin/logstash` 启动它，状态在 `path.data`（持久队列、死信队列、节点 uuid、密钥库）。

本机 `D:\code\logstash-9.5.2` 是发行包，不是 Elastic 的 git 树：没有 `src/main/java`，没有单元测试。Java 在 `logstash-core\lib\jars\logstash-core.jar`，编排在 `logstash-core\lib\logstash`。预言机就是这个能跑的旧进程。类级细节需要时对照上游 tag `v9.5.2` 的公开源码，期望值仍从本机二进制跑出来，禁止用新实现的输出回填测试。

旧进程只在开发时当对照，不链接进 `rstash`。用户跑 Rstash 时不需要安装 JDK。

- 照搬：
  1. 边界行为用 Rust 重新实现：仍读原来的 `.conf`，仍认原来的 CLI 参数，仍写出原来的事件 JSON，退出码仍对齐。这些解析和执行全是 Rust 结构体和 enum。不把 Java 类留下来，也不把 Java 类层次翻译成 trait 继承树。
  2. 插件分清单，每一项都是 Rust 实现。没实现的插件明确报错并退出，不静默跳过，也不退回 Ruby gem。清单随切片更新。
  3. JSON、时间、YAML、HTTP 用纯 Rust crate。配置语法是产品，对照 `logstash-core\lib\logstash\compiler\lscl\lscl_grammar.treetop` 用 Rust 重写解析器。treetop 文件只当规格读，不打进程序。
- 不照搬：不留任何第二种语言运行时。旧的 `.rb` 和 `.java` 插件都按行为用 Rust 重写。
- 源语言和构建：Java 21 + JRuby 10.0.6.0。上游是 Gradle（核心）和 Rake/Bundler（gem）。运行时入口是 `bin/logstash` → `org.logstash.Logstash` → `LogStash::Runner` → `LogStash::Agent`。
- 公开表面：CLI 标志（`-e`、`-f`、`-t`、`-w`、`-b`、`--path.settings`、`--path.data`、API 端口）；LSCL 配置；事件字段 `@timestamp`、`@version`、`tags`、`[@metadata]`、`%{sprintf}`；`logstash.yml` / `pipelines.yml`；内存队列、持久队列、死信队列的可观察行为；监控 API 路径；`logstash-plugin`、`pqcheck`、`pqrepair`、`logstash-keystore`。
- 预言机：`D:\code\logstash-9.5.2\bin\logstash.bat`。发行包里没有 JUnit / RSpec。

管道在数据面上的角色固定为 input → queue → filter → output。配置语言不换成另一种 DSL。

## 语言边界

Cargo 依赖只允许纯 Rust crate。不要引入会编译 C 或 C++ 的包（典型信号是依赖 `cc`、`cmake` 或 `bindgen`）。操作系统接口（Windows API）不算第二种业务语言。

某一片如果只有 C 绑定才能对齐行为，开工前停下来问。默认继续找纯 Rust 实现。已知会碰到这个选择的地方：

- Grok 的正则方言来自 Oniguruma。优先纯 Rust 正则；对不齐的模式记入有意差异，不默认链接 C 库。
- Kafka 客户端优先纯 Rust 实现，不用 librdkafka。
- `logstash-keystore` 在 9.5.2 里是 PKCS12，不是 JCEKS。纯 Rust 还没读写这份文件，不在进程里启动 JVM。

## 它有哪些模块

- 进程入口。`bin/logstash` 拉起 JVM，再进入 Ruby CLI。旁边还有 `logstash-plugin`、`logstash-keystore`、`pqcheck`、`pqrepair`。这些是公开命令，晚于管道核心。
- Agent。`logstash-core/lib/logstash/agent.rb` 管多管道、热加载、信号和监控 HTTP。控制面，不进第一片。
- 配置语言 LSCL。Treetop 语法约 247 行：`input` / `filter` / `output`、插件属性、`if/else/elsif`、比较、`in`、`=~`、`and/or/xor/nand`。`config/grammar.treetop` 是遗留 AST，执行走 LSCL。
- 编译。Ruby 把语法树交给 `org.logstash.config.ir.ConfigCompiler`，得到 `PipelineIR`。`CompiledPipeline` 再交给 worker。
- 执行。`JavaPipeline` 为每个 input 起线程，按 `pipeline.workers` 起 `WorkerLoop`。默认 batch 125、delay 50ms、workers 等于 CPU 数、`queue.type` 为 `memory`、`pipeline.ordered` 为 `auto`。
- 事件。`org.logstash.Event`：开放字段表、独立的 `@metadata`、`@timestamp`、`tags`、`sprintf`、`cancel`。这是后面每一片的叶子。
- 队列。内存队列是批读取。持久队列是 `org.logstash.ackedqueue` 的 mmap 页（V1/V2）加 checkpoint，路径 `path.data/queue/<pipeline_id>/`。死信队列是另一套分段文件。
- 插件契约。Java：`co.elastic.logstash.api` 的 Input / Filter / Output / Codec。Ruby：`LogStash::Inputs::Base` 等。发现方式是 gem 元数据 `logstash_plugin: true`。核心 JAR 自带 stdin、generator、uuid、stdout、sink、plain、line、dots。Ruby 自带 `pipeline` 输入输出。其余在发行包 `Gemfile` 里。
- 设置。`environment.rb` 登记默认值，`logstash.yml` 和 CLI 覆盖。
- 可观测性。默认 `127.0.0.1:9600` 起。路径包括 `/`、`/_node`、`/_node/stats`、`/_node/hot_threads`、`/_stats`、`/_health_report`。
- x-pack。集中配置、内部监控管道、GeoIP 库下载、许可证。不在管道能跑通之前做。

## 技术栈替换

替换的是运行时角色。组合根只在二进制的 `main`。第一片只有一个 crate `rstash`，二进制同名。出现「测试不想启动管道」时再拆领域 crate。管道线程模型保持阻塞。tokio 等到某个插件确实要异步 IO 再引入。

- JRuby 启动和 `LogStash::Runner`：Rust `main` 手写组装。CLI 用 clap，标志与旧进程对齐。切片 6。
- Treetop LSCL：手写递归下降，规则对照 treetop。不引入 Ruby。切片 2–3。
- `ConfigCompiler` / `CompiledPipeline`：enum 图（插件、if、队列边界）。切片 4。
- `WorkerLoop`、input 线程、内存队列：`std::thread` 加带超时的批队列。默认 125 / 50ms / CPU 数要锁住。切片 5。
- `org.logstash.Event`、`FieldReference`、`sprintf`：结构体。`@metadata` 与正文字段分开。切片 1。Java 字符串若按 UTF-16 下标切片才需要码元索引；本片字段路径按字符，不用下标截断。`@timestamp` 是带时区的时刻，不把本地时间当成 UTC。
- 事件 JSON（json / json_lines codec）：serde。事件是开放 map，不要 `deny_unknown_fields`。`@timestamp` 的字符串格式用 fixture 锁。切片 5 之后的 codec 片。
- Ruby 插件基类和 gem 发现：Rust trait，注册表里是编译进二进制的 Rust 插件。不扫描 gem，不执行 `.rb`。未注册名字启动失败。
- Log4j：`tracing`。日志句子不是契约。
- 内存队列：标准库。持久队列：`memmap2`，页格式对照旧文件和 `pqcheck`。死信队列同理。靠后的切片。
- `logstash.yml`：serde_yaml 收成一个结构体，在 `main` 加载一次。密钥只来自环境变量或现有 keystore 文件，不写进仓库。
- 监控 API：标准库 TCP。只在 `api.http.port` 有值时听 `127.0.0.1`，管道返回后关掉。JVM 堆、GC 和 hot threads 不编造。`/_node` 和 `/_node/stats` 不写 `jvm`。`/_node/hot_threads` 的 `threads` 是空数组。`/_health_report` 只有 `status: green`，没有指标树。
- Elasticsearch / Kafka / JDBC：用纯 Rust 客户端说原来的协议。各算一片插件。
- Grok：行为用 fixture 锁。正则库必须是纯 Rust。对不齐的 Oniguruma 语法记入有意差异，开工前问。
- GeoIP：用纯 Rust 的 MaxMind 读取库。下载器属于 x-pack，更晚。
- Java KeyStore：文件格式仍是公开表面，用纯 Rust 读写。做不到就停下来问，不启动 JVM，也不自研密码学。

## 有意差异

- 未实现的插件。旧：加载 gem 并运行。新：打印插件类型和名字，非 0 退出。原因：按波次补齐，禁止假装成功。已确认：先做管道，再迭代到完整。终态要消掉这条。
- 进程里不保留 Java、JRuby、Ruby。旧：插件是 `.java` / `.rb`，宿主是 JVM。新：同一行为由 Rust 实现，二进制不嵌入第二种语言。已确认。
- 日志原文和异常类名。旧：Log4j / Ruby 异常。新：`tracing` 和 `Result`。原因：没有采集规则依赖原文。
- 二进制名。旧命令是 `logstash`。新二进制叫 `rstash`，参数对齐。原因：仓库名是 Rstash。
- 监控 API 不编造 JVM 堆、GC 和线程栈。旧 JSON 有 `jvm`，hot threads 是 JVM 转储。新响应省略 `jvm`，`hot_threads.threads` 是空数组。`os.name` 是 Rust 的 `std::env::consts::OS`，不是 Java 的 `Windows 10`。事件耗时字段是 0，因为没有采集。默认不监听：官方默认扫 `9600..9700`，短测试会占住端口。设置了端口才在这次 `run` 期间听 `127.0.0.1`，返回后停止。`?human` 仍返回 JSON。`config.reload.automatic: true` 报 `pipeline reload is not implemented`，没有文件监视。没有总线时多条管道仍是一条接一条跑，第二条会因为端口已被占用而失败。有 `pipeline` 总线时几条管道一起跑，监控 API 只由第一条打开。已确认。
- `nand` / `xor` 和 `and` / `or` 混用时两边都拒绝。旧报错文本是 JRuby `Method#inspect`。新文本是 `ArgumentError: Unexpected operator nand` 或 `xor`。已确认：失败条件对齐，不复制 JVM 方法签名。
- grok 的 `timeout_millis` 不打断匹配。旧实现用 Ruby `Timeout`。新实现把正则跑完。原因：没有单独的超时线程；跑不完的模式会一直占着这次调用。
- `multiline` 的 `auto_flush_interval` 不是后台计时器。有限的 `file` 输入在结束时 flush；`stdin` 不 flush。`charset` 只认 `UTF-8`。
- file 的 tail 读完当前新增内容就返回，不会一直盯着文件。旧进程在 `subscribe` 里停住，直到收到停止信号。这里还没有停止信号。
- tcp、udp、http、beats 的监听在对端关掉、端口空闲之后返回。旧进程停在 `stop?` 上。这里还没有停止信号。`ssl_enabled => true` 直接报未实现，不链接 TLS。tcp 输入不做反向 DNS，`host` 写的是对端数字地址。beats 只收 lumberjack v2 的窗口帧和 JSON 帧，压缩帧报未实现。tcp 输出只做 client。http 输出只做 `format => json` 和 `message`。
- 持久队列在整次运行成功之后才 ack。中途崩溃会把已经输出过的事件再放出来一次。多个 worker 不按批 ack，避免乱序确认。`queue.checkpoint.acks`、`queue.checkpoint.writes`、`queue.max_bytes` 还不生效。`queue.compression` 只接受 `disabled` 和 `none`，其它值报未实现。死信队列读完磁盘上已有的段就返回，不等下一条。`dead_letter_queue.retain.age` 还没有定时清理。段里的插件类型、id 和原因按 UTF-8 写。Java 的 `String.getBytes()` 用 JVM 默认字符集，ASCII 一致。
- elasticsearch 输出的 bulk 在 `compression_level` 不是 0 时用 gzip 的 stored deflate 块。解压后的 NDJSON 与插件一致，压缩字节不是 zlib level 1。失败的 bulk 只请求一次，不按官方那样一直重试。`https`、`ssl_enabled`、`sniffing`、`api_key`、`cloud_id` 报未实现。只连 `hosts` 里的第一个地址。
- elasticsearch 输入的 `schedule` 报未实现。`slices` 大于 1 报未实现。搜索在重试次数用完后让这次运行失败，官方是记一条日志然后继续、不产生事件。过滤器的 ES|QL 报未实现。查找失败打 `tag_on_failure`，显式写成空数组时不加标签。
- kafka 只做 `PLAINTEXT`，`bootstrap_servers` 只用第一个地址，压缩、`SASL` 和其它 `security_protocol` 报未实现。输出请求是 Metadata v4 和 Produce v3。输入做一次 Metadata、OffsetFetch、必要时 ListOffsets、Fetch v4 和 OffsetCommit，然后返回。官方消费者会一直 poll 到停止。记录批是 magic 2、CRC-32C。`topics_pattern`、schema registry、`consumer_threads` 大于 1 报未实现。失败不无限重试。
- jdbc 只做 `jdbc:postgresql://` 的简单查询（trust、明文密码、md5）。其它驱动报未实现。`schedule`、`interval`、`period` 报未实现，因为官方会一直跑。分页和字符集转换报未实现。预处理语句的 `?` 被内联成字面量，不走扩展协议。`ssl` 报未实现。
- `pipeline` 输入输出把事件克隆到进程内地址，和 `rubyClone` 一样。接收方不在本进程、发送方不在本进程、或地址图有环时直接报错返回，不按官方那样一直重试到停止。`ensure_delivery => false` 且当时没有接收方时丢掉事件。同一地址只能有一个输入。已确认。
- `plugin list` 只列出编译进这个二进制的 gem，版本是 9.5.2 发行包里的版本。`jdbc_streaming`、`jdbc_static` 和 `elastic_agent` 别名不列出，因为配置名还不接受。`install`、`remove`、`update`、`pack` 会改 Ruby gem，这里报未实现。keystore 文件是 PKCS12，后面还拼一段打乱的口令；这个进程不读也不写。`keystore` 子命令能打出 9.5.2 的帮助，真正的 create/list/add/remove 报未实现。已确认。

## 切片

依赖只指向已经通过的叶子。一轮只实现一片。

- 第 1 片。事件、字段路径、`sprintf`、`@metadata`、`tags`、`@timestamp`。验收：`cargo test event_fields`，官方行为再加 `cargo test --test official_suite`。不引入 tokio、axum、clap。状态：通过。`@timestamp` 文本与 9.5.2 一致：纳秒为 0 时固定 3 位小数，否则按 3/6/9 位去掉末尾的零组。`%{+pattern}` 用 Joda 风格，`%{{pattern}}` 用 Java 风格。两种都认 `y` `Y` `M` `d` `D` `w` `s`、单引号字面量和普通字符；`%{+%s}` 是 epoch 秒。没实现的字母返回错误，不猜。已有数组用数字下标读取，负数从末尾数；`setField("[foo][0]")` 在父级还不存在时建的是键为 `"0"` 的 map。`tags` 只能是字符串、字符串数组或空；构造时如果 `tags` 是 map，改存到 `_tags` 并打上 `_tagsparsefailure`。字段路径按 Unicode 标量扫描，预言机里的路径都是 ASCII。
- 第 2 片。LSCL 子集：注释、三段式、插件、属性、字符串、数字、数组、哈希。验收：`cargo test parse_sections`。状态：通过。语法按 `lscl_grammar.treetop` 的顺序做递归下降。`config.support_escapes` 默认 false，引号里的反斜杠原样保留；为 true 时才走 `StringEscape.process_escapes`。没有 `true` / `false` / `null` 关键字，两个字符以上的裸词是字符串。裸词至少两个字符，哈希键一个字母会报 treetop 那种 `Expected [A-Za-z0-9_]`。数字末尾只有点（`1.`）语法上能读出来，随后按 Ruby `Float()` 报 `ArgumentError`。整数走 Ruby `Integer()`：前导 0 是八进制，`010` 是 8，`08` 和 `09` 报 `ArgumentError`。重复属性：标量不同变成数组，相同保留一个；数组拼接；哈希按 `hash_merge_with_dups` 合并。哈希字面量里的重复键报 `Duplicate keys found`。input/output 上 `codec` 的值如果变成数组（写了两次，或写成 `codec => ["json"]`）报 multiple codec。插件值（例如 `codec => json { }`）的类型是 codec。
- 第 3 片。条件：`if/else/elsif`、比较、`in`、`=~`、`and/or/xor/nand`。验收：`cargo test conditions`。状态：通过。`elsif` 不是关键字，`else if` 和连写的 `elseif` 才会变成嵌套 if。布尔运算是 `Condition#join_conditions`：`and` 优先级 2，`or` 优先级 1，只有左边优先级严格更高才弹出，所以同级是右结合。单独的 `nand` 是 `!(left && right)`，单独的 `xor` 是 `(!(left) && right) || (left && !(right))`；它们和别的布尔运算混用就报错。`=~` 右边的字符串会变成正则。方法调用没有实现，`length([aa])` 会退化成字段 `[aa]`，这是 9.5.2 的实际行为，不要改成报错。
- 第 4 片。编译成执行图：filter 顺序、input/output 并列、if 分支。验收：`cargo test compile_graph`。状态：通过。空段是 noop；只有一个语句时不包一层；多个 filter 是 `do-sequence`，多个 input 或 output 是 `composed-parallel`。if 的空分支也是 noop。语句文本按 Java `toString` 的缩进来，方便和预言机逐字比较。插件参数里再嵌一个插件时，JRuby 的 `Hash#inspect` 会带上变化的对象 id，预言机改成按 `PluginDefinition` 打印，Rust 也按这个稳定形状输出。
- 第 5 片。内存管道跑通一条最小配置：`generator` count + `stdout`。批大小 125、delay 50 ms、worker 数等于 CPU。验收：`cargo test pipeline_generator_stdout`。状态：通过。没有重写解析器。`generator` 的 `count` 必须大于 0；0 表示无限生成，这条管道不会一直跑。ECS 默认 `v8`，字段走 v1：`[host][name]`、`[event][sequence]`、`[event][original]`。`stdout` 不写默认的 `rubydebug`，配置里要显式 `codec => plain` 或 `codec => line`，否则报未实现并退出。
- 第 6 片。CLI：`-e`、`-f`、`-t`（配置对则打印 `Configuration OK` 并退出 0，错则非 0）、`-w`、`-b`，另外认 `--path.settings`。验收：`cargo test cli_test_and_exit`。状态：通过。没实现的插件在 `-t` 和正式运行时都是非 0。
- 第 7 片。内置 codec `plain`/`line` 和过滤器 `drop`、`mutate` 3.6.0。验收：`cargo test drop_mutate_and_line_codec`，官方样本再加 `cargo test --test official_plugins --test mutate_spec`。状态：通过。`drop` 的 percentage 100 一定取消事件，0 不取消。`mutate` 的顺序是 coerce、rename、update、replace、convert、gsub、uppercase、capitalize、lowercase、strip、split、join、merge、copy，然后 add_field、remove_field、add_tag、remove_tag。运行期失败打 `tag_on_failure`（默认 `_mutate_error`），不把异常抛出去。register 阶段拒绝未知 convert 类型和长度不是 3 的倍数的 gsub。`gsub` 的替换是字面量，`$` 不当反向引用。`line` 只在遇到分隔符时吐出完整行，剩余部分留到 flush，flush 出来的事件没有 sequence。`=~` 只执行字面量、`^`、`$` 和一段 `.*`。mutate 官方测例里的两处 grok 只认 `%{WORD:名字}` 和 `(?:字面量)`；别的 grok 模式报未实现。完整 grok 仍是波 B。
- 第 8 片。`logstash.yml` 子集（`pipeline.workers`、`pipeline.batch.size`、`pipeline.batch.delay`、`pipeline.ecs_compatibility`）和 `pipelines.yml`（`pipeline.id` 加 `config.string` 或 `path.config`）。验收：`cargo test pipelines_do_not_mix_events`。状态：通过。每条管道单独一条内存队列，命令行给了 `-e` 或 `-f` 时不读 `pipelines.yml`。

第 5 片通过之后才进入插件波次。每一波仍是一片一片做，每片用旧 `bin/logstash` 的 stdout 或退出码验收。

- 波 A：stdin、dots、sink、uuid。状态：通过。验收 `cargo test --test waves`。`stdin` 默认按行读，`Settings.stdin` 有值时用那一段文本，否则读到 EOF。`dots` 每个事件编码成一个 `.`，不能解码。`sink` 丢掉输出字节，事件仍记在运行结果里。`uuid` 要 `target`；`overwrite` 默认 false，写出的是版本 4 的十六进制字符串。
- 波 B：date、json、kv、dissect、csv、grok、clone、fingerprint、prune。状态：grok 通过，其余过滤器仍是各自 gem 的一部分选项。`grok` 4.4.4：`%{NAME}`、`%{NAME:字段}`、`%{NAME:字段:int}`、`%{NAME:字段:float}`、`pattern_definitions`、`patterns_dir`、`break_on_match`、`named_captures_only`、`keep_empty_captures`、`overwrite`、`target`、`tag_on_failure`。ECS `v8`/`v1` 用 `patterns/ecs-v1`，`disabled` 用 `patterns/legacy`，内容是 patterns-core 4.3.4。每一条内置模式都能编过。`timeout_millis` 收下但不打断匹配。JRuby 会把嵌套的 `?*` 收成 `*`，这里同样收成 `*`。`date` 认 `UNIX`、`UNIX_MS`、`ISO8601` 和一段 Joda 字母（`y M d H m s S`）。`json` 解析失败打 `_jsonparsefailure`。`kv` 用字面量 `field_split` / `value_split`。`dissect` 认普通字段、`?` 跳过、`+` 拼接、`&` 间接字段。`csv` 认 `columns`、`separator`、`convert` 的 integer/float/boolean。`clone` 在 ECS 关闭时写 `type`，打开时加 tag，原事件保留。`fingerprint` 的 `SHA1`、`SHA256`、`UUID`、`PUNCTUATION` 可用，其它方法报未实现。`prune` 只处理顶层字段名。同一批还接上了 `split`、`urldecode`、`truncate`、`syslog_pri`、`de_dot`、`anonymize`（HMAC-SHA1 / HMAC-SHA256）、`sleep`。
- 波 C：json、json_lines、rubydebug、multiline codec。状态：通过，带下面的限制。`json` 编码是 `Event::to_json`，解码失败把原文放进 `message` 并打 `_jsonparsefailure`。`json_lines` 在 JSON 后加分隔符，默认换行。`rubydebug` 按 amazing_print 的形状输出，键用引号，字符串值用引号，末尾有换行。`stdout` 不写 codec 时用 `rubydebug`。`multiline` 3.1.2：`pattern`、`what`（previous/next）、`negate`、`max_lines`（默认 500）、`max_bytes`（默认 10 MiB）、`multiline_tag`。模式名走 legacy 模式库，和 `Patterns::Core.path` 不带参数一致。`file` 输入结束时 flush，和 `exit_flush` 一致；`stdin` 不 flush，最后一段留在缓冲里。`auto_flush_interval` 不是后台计时器。`charset` 只认 `UTF-8`，别的字符集报未实现。`multiline` 不能当输出编码。
- 波 D：file、tcp、udp、http、beats。状态：通过，带下面的限制。sincedb 在插件里，不在 core。一行是 `inode major minor position changed_at path`；只有四列的旧行没有时间和路径。Windows 的 inode 是 `volumeSerial-fileIndexLow-fileIndexHigh`，设备号是 0。`mode => read` 从开头读，已有检查点就从检查点接着读，读完默认删文件（`file_completed_action => delete`）。`tail` 第一次见到文件时 `start_position => end` 停在文件末尾。这一趟读完就返回，不会一直 tail。`tcp` 输入默认 server，`port` 必填，默认 codec 是 `line`，ECS 关闭时写 `host`、`port` 和 `[@metadata][ip_address]`。`tcp` 输出默认 client，默认 codec 是 `json`。`udp` 输入默认 codec 是 `plain`，ECS 关闭时把来源地址写进 `host`，打开时写 `[host][ip]`。`udp` 输出的 `port` 先做 sprintf。`http` 输入默认 8080，`application/json` 按 json codec 解 body，`user` 设置时要 Basic 认证，应答默认 200。`http` 输出要 `url` 和 `http_method`。`beats` 收 lumberjack v2 的 `W` 和 `J` 帧，并回 `A` ack。验收 `cargo test --test file_sincedb --test netio`。
- 波 E：持久队列页格式和 `pqcheck`/`pqrepair`，然后死信队列。状态：通过，带上面的限制。`queue.type: persisted` 把事件写成 Jackson CBOR，帧仍是 `MmapPageIOV2`。页写满后序号接着上一页，不从 1 重新开始；整页 ack 掉、尾页被删掉之后，新页的序号再从 1 开始。再次打开一个还有元素的尾页时，先把尾页封成 `checkpoint.N`，再开一个空的下一页。`rstash pqcheck 目录` 读 `checkpoint.head` 并校验它指向的那一页。`rstash pqrepair 目录` 按 `PqRepair`：删 `checkpoint.*.tmp`，删已经完全确认的页和检查点，删没有页的检查点，删短于 18 字节的页，并为除最高页以外缺检查点的页按页字节重建检查点。死信队列段是 `N.log`：版本字节 `1`，记录头 13 字节（`c`/`s`/`m`/`e`、长度、总长度或 -1、CRC32），负载是 `DLQEntry`。`dead_letter_queue` 输入读 `path/pipeline_id` 下已有的段，把 `plugin_type`、`plugin_id`、`reason`、`entry_time` 写进 `[@metadata][dead_letter_queue]`。`commit_offsets` 默认 true，sincedb 是版本字符 `1`、路径、偏移。`clean_consumed` 要求同时打开 `commit_offsets`。9.5.2 的 `Event.deserialize` 能读这里写出的队列事件，`DeadLetterQueueReader` 能读这里写出的段。验收 `cargo test queue::` 和 `cargo test dlq::`。
- 波 F：elasticsearch、kafka、jdbc 的协议行为。状态：输出、输入、过滤器、kafka 输出和 jdbc 的 PostgreSQL 一次性查询已接上，限制见上。elasticsearch 输出是 logstash-output-elasticsearch 12.1.6。ECS 打开且 `data_stream` 为 `auto` 时，bulk 动作是 `create`，索引是 `logs-generic-default`，文档补上 `data_stream.type/dataset/namespace`。ECS 关闭且索引仍是默认值时，`ilm_enabled => auto` 把 `_index` 改成别名 `logstash`，HEAD/PUT 发行包里的 composable 模板，创建 `<logstash-{now/d}-000001>` 和策略 `logstash-policy`。动作行保留 JrJackson 写出的 `"_id":null` 和 `"routing":null`。模板 JSON 来自该 gem 的 `templates/ecs-*`。文档状态 400/404 在死信队列打开时写入 DLQ，否则丢掉；409 丢掉。其它状态让这次运行失败。输入是 5.3.2：Elasticsearch 8 用 point-in-time 和 `search_after`，7 用 scroll，聚合、ES|QL、`docinfo` 和 `tracking_field` 会写出事件。过滤器是 4.4.1：DSL 查询字符串走 `q`，`query_template` 走 JSON body，失败打标签。kafka 输出是 12.1.5 的明文 Produce，输入是同版本的一次 Fetch。jdbc 是 5.6.4 里没有调度的那一次查询。验收 `cargo test --test elasticsearch --test elasticsearch_query --test kafka --test jdbc` 和 `cargo test kafka::`。
- 波 G：监控 API、热加载、`pipeline` 输入输出。状态：监控 API 和 `pipeline` 输入输出已接上，限制见上。`GET /` 带 9.5.2 的 `build_date` `2026-08-17T18:16:06+00:00`、`build_sha` `81753940099b4c9df5dba0da3fe6adb2f190a880`、`build_snapshot` false，并合并节点元数据。`/_node` 有 pipelines 和 os，没有 jvm。`/_node/stats` 有这次运行实际数过的 `events.in`、`events.filtered`、`events.out`，没有 jvm 和 flow。`events.in` 只数这次输入推进队列的事件，不数磁盘回放。`output { pipeline { send_to => ... } }` 把克隆送到 `input { pipeline { address => ... } }`，接收方补上 `type`、`tags` 和 `add_field`。热加载没有监视器。验收 `cargo test --test api --test pipeline_bus`。
- 波 H：plugin 子命令、keystore、x-pack。状态：`rstash plugin list` 已接上，可按名字、`--group`、`--verbose` 过滤。`--installed` 表示用 install 命令另装的插件，这里没有，所以是 `No plugins found`。keystore 的帮助文本已接上，PKCS12 读写还没有。x-pack 还没做。Gemfile 里其余插件按这个顺序继续，直到清单清空。验收 `cargo test --test plugin_cmd`。

## 插件清单

已对齐：`generator`、`stdout`（codec 可以是 `plain`、`line`、`json`、`json_lines`、`dots`、`rubydebug`；缺省是 `rubydebug`）、`plain`、`line`、`drop`、`mutate` 3.6.0、`stdin`、`dots`、`sink`、`uuid`、`json` 过滤器和 codec、`json_lines`、`multiline`（见波 C）、`kv`、`dissect`、`csv`、`date`、`clone`、`split`、`prune`、`fingerprint`（SHA1/SHA256/UUID/PUNCTUATION）、`urldecode`、`truncate`、`syslog_pri`、`de_dot`、`anonymize`、`sleep`、`heartbeat`（`count` 必须是非负整数；`-1` 会一直跑，这里直接报错）、`exec`（要 `interval`，命令跑一次就结束；`schedule` 报未实现）、`file` 输入（官方 sincedb 文本；`mode => read` 或 tail 的一次读取；codec 可以是 `multiline`）和 `file` 输出（追加写）、`tcp` 输入输出、`udp` 输入输出、`http` 输入输出、`beats` 输入（见波 D）、持久队列（`queue.type: persisted`）、`pqcheck`、`pqrepair`、`dead_letter_queue` 输入（见波 E）、`elasticsearch` 输出、输入和过滤器（见波 F）、`kafka` 输入和输出（明文，输入只拉一次）、`jdbc` 输入（只做 PostgreSQL 的一次性查询）、`pipeline` 输入和输出（见波 G）。`null` 与 `sink` 一样不写 stdout。`grok` 展开 patterns-core 4.3.4 的全部模式。

未实现（出现在配置里必须报错并退出非 0）：上面没有点名的 Gemfile 插件，包括 jdbc 的非 PostgreSQL 驱动、elasticsearch 过滤器的 ES|QL、热加载的文件监视、keystore 的 PKCS12 读写、x-pack。`plugin install` / `remove` / `update` 也报未实现。`exec` 的 cron、`heartbeat` 的无限循环、file 的持续 tail、这些网络插件的 TLS，也还没有。input 段里的 `if` 报未实现，不猜。

## 不做

- 不在 Rstash 里保留、嵌入或调用 Java、JRuby、Ruby、Python。
- 不把会编译 C 或 C++ 的 crate 写进 `Cargo.toml`。某一片做不到纯 Rust 时先问，不自行加 C 依赖。
- 不按 Java 包建一排空 crate，不写 DI 容器或注解扫描。
- 不在第 1 片引入 tokio、axum、clap。
- 不把 x-pack 提前做完。监控 API 不是常驻 agent，也没有 JVM 指标。
- 不修改旧 Logstash 目录里的任何文件。旧目录只在开发时当对照。跑预言机时 `--path.data` 和 `--path.logs` 指向本仓库 `target/`，避免写入发行包。
- 发现旧行为像 bug 时记入有意差异，未确认不改。

## Git

远程：`https://github.com/Shitiumisakana/Rstash.git`。每一片 `cargo test` 通过并更新本文件之后提交并推送。访问 GitHub 走系统代理 `http://127.0.0.1:7897`，不要直连。单次命令用 `git -c http.proxy=http://127.0.0.1:7897`，不要改 git config。推送前 `origin/master` 是 `2fd2b34`。这一片接上 `plugin list`。keystore 只打印帮助，PKCS12 文件还不读写。x-pack 还没做。推送失败就保留本地提交，在本文件写明失败原因，下一位先推再写代码。不提交密钥、`path.data`、日志。`.gitignore` 忽略 `target/`。
