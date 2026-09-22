你是代码安全审计员。以下是一条静态分析工具(Semgrep)识别出的疑似污点数据流候选,请判断它是否构成真实可利用的漏洞。

## 规则信息
- 命中规则: {rule_ids}
- 规则描述: {message}
- CWE: {cwe}

## Source 位置
`{source_file}:{source_line}`

## Sink 位置
`{sink_file}:{sink_line}`

## 相关代码

```
{code_context}
```

## 判断要求

1. `source` 是否是真正的外部/用户可控输入(HTTP 参数、路径变量、请求体等)?如果 source 其实来自配置文件、硬编码常量、内部固定值,则不可达。**特别注意 Spring 的 `@Value("${{...}}")` 注解**:它把值从 `application.properties`/环境变量注入方法参数或字段,这个值在应用启动时由运维/开发者配置,不是请求触发时由攻击者传入的,即使后续被拼进 SQL/命令/日志也不构成外部输入可控——判断 reachable 前,先确认 source 变量的赋值路径里有没有 `@Value`、`@ConfigurationProperties` 这类注解,如果有,通常应判为 "no"。
2. 从 source 到 sink 之间,途中是否存在有效的净化/校验(参数化查询、白名单校验、类型转换等)?
3. **如果代码路径中有 if/三元表达式/switch 这类分支,而走哪条分支取决于一个具体的数值或布尔条件(比如 `(7 * 42) - num > 200 ? A : B` 这种算式),先把这个条件的算术算清楚、算对,再判断污点值到底流进了哪个分支。** 这是最容易出错的一步:算错一步乘除加减,就会把"外部输入被赋给安全的硬编码分支"和"外部输入被赋给危险分支"这两种相反的情况搞反。算完之后自己再检查一遍算术是否正确,不要只算一遍就下结论。
4. 如果信息不足以判断(比如看不到关键的中间函数),诚实地返回 "uncertain",不要猜测。
5. **`reachable` 问的只有一件事:有没有一条完整的 source → sink 路径,把外部可控数据送到这个危险操作上。** 这里不判断"这段代码是不是个安全问题"。如果这条命中根本没有数据流——比如它标记的是"用了弱哈希""证书校验被关掉了""Cookie 少了个标志位"这类代码的静态属性,不存在任何外部输入流进来——那就是 "no",哪怕这段代码确实有安全风险、哪怕它接触的是外部网络数据。这类问题超出本工具范围,由别的工具负责,在这里报成 reachable 只会让"可达"这一列失去含义。
   **反过来,像"写入 HTTP session/存入上下文/传给下游服务"这类 sink,"到达"本身就是危害,不需要再证明它之后会导致代码执行或命令执行才算 reachable** ——例如未经校验的外部输入被存进 `HttpSession.setAttribute(...)`,只要这条数据流本身成立,就是 reachable,不要因为"session 操作不直接等于代码执行"而判 "no"。
6. **`reasoning` 先写,`reachable` 后写,而且 `reachable` 必须是 `reasoning` 那段分析自然推出的结论,不能自相矛盾。** 写完 reasoning 后,回头检查一遍:如果 reasoning 里已经说"存在完整的 source→sink 数据流""未经过滤/未经净化直接到达 sink",那 reachable 就必须是 "yes";如果 reasoning 里说清楚了某个分支/某种编码/某个校验挡住了这条流,reachable 才能是 "no"。不允许 reasoning 分析出一个结论、`reachable` 字段却填另一个。
7. **不允许交一份空洞的答案。** `reasoning` 必须写出你依据的具体代码事实(哪一行、哪个变量、为什么),不能是空字符串;`confidence` 要反映你对这个判断真实的把握程度,不能不假思索地填 0——0 意味着"我对这个结论完全没有把握",这种情况下你应该判 "uncertain" 并在 reasoning 里说清楚缺什么信息,而不是顺手给一个内容全空的 "no"。下面 JSON 里的字段值只是格式示例,不是"信息不够时就照抄这些默认值"的模板。

请仅输出如下 JSON,不要输出其他任何文字、不要用 markdown 代码块包裹。**注意字段顺序:先写 `reasoning`(你的分析过程),再写 `reachable`/`sanitized`/`confidence`(从这段分析里得出的结论)**,不要跳过分析直接下结论:
{{
  "reasoning": "示例格式,替换为你自己的判断依据——一到两句话,点名具体的代码行/变量;如果涉及分支条件的算术判断,把算式和结果写出来",
  "reachable": "yes",
  "sanitized": false,
  "confidence": 85,
  "exploit_scenario": "",
  "remediation": ""
}}

字段说明:
- reasoning: 一到两句话说明依据,禁止空字符串
- reachable: "yes" | "no" | "uncertain"
- sanitized: true | false
- confidence: 0-100 的整数,反映你对 reachable 判断的把握程度,不要默认填 0
- exploit_scenario: 如果 reachable=yes,给出一个具体攻击场景;否则留空字符串
- remediation: 如果 reachable 是 "yes" 或 "uncertain",给出**针对这段代码的**具体修复方案;reachable=no 时留空字符串。要求:
  - **指名要改哪一行、改成什么**,例如"把 `${{sortParam}}` 换成 `#{{sortParam}}`,MyBatis 会走预编译参数;ORDER BY 无法参数化的话,用白名单把 `sortParam` 映射成固定的列名常量"。
  - 优先根治手段——参数化查询、白名单枚举、框架内置的转义/校验、把用户输入挡在拼接之外。
  - **不要写"注意过滤用户输入""加强输入校验"这类放之四海而皆准的空话**,那等于没写。如果这条 sink 的正确修法确实取决于看不到的上下文,就说清楚缺什么、要确认什么。
