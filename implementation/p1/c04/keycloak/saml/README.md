# C04 Keycloak 合成 SAML Broker 真实运行验证

状态：`RUNTIME_VERIFIED / SYNTHETIC_ONLY`

本目录记录 C04 在 Keycloak 26.7.0 上的两 Realm 真实协议验证。测试使用：

- `c04-saml-upstream`：作为上游 SAML 2.0 IdP；
- `c04-saml-broker`：作为下游 SAML SP，并向合成门户提供 OIDC；
- `synthetic-saml-operator`：两个 Realm 中预创建并精确关联的合成用户；
- `synthetic-saml-unlinked`：只存在于上游 Realm、用于验证禁止 JIT 的合成用户；
- `.example` 域名、随机回环端口、自签测试证书和一次性随机凭据。

它不使用任何 Target Enterprise、企业目录、OA、U9、BI、真实邮箱或真实账号。

## 运行

```sh
sh scripts/run-c04-keycloak-saml-tests.sh
```

默认使用：

- `implementation/p1/c04/keycloak/keycloak-distribution.lock.json` 中锁定的
  Keycloak 26.7.0、下载地址和 SHA-256；
- `/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`。

如 OpenJDK 21 位于其他位置，只能显式指定：

```sh
C04_KEYCLOAK_JAVA_HOME=/absolute/path/to/jdk-21 \
  sh scripts/run-c04-keycloak-saml-tests.sh
```

## 测试实际做什么

测试通过 Keycloak Admin API 和真实元数据完成以下配置：

1. 创建上游 IdP Realm、下游 Broker Realm 和 OIDC PKCE 公共客户端；
2. 读取上游 SAML IdP descriptor，并从其中取得签名证书；
3. 在 Broker Realm 创建 SAML Identity Provider，开启：
   - `validateSignature=true`
   - `wantAssertionsSigned=true`
   - `wantAuthnRequestsSigned=true`
   - `signSpMetadata=true`
4. 读取 Broker 的已签名 SP descriptor，并取得 Broker 签名证书；
5. 在上游 Realm 创建 SAML client，要求 AuthnRequest 签名，同时签名
   Response 和 Assertion；
6. 在 Broker Realm 创建独立 First Broker Login flow，将 Keycloak 内置
   `Deny access` authenticator 设为 `REQUIRED`；只有预先关联的身份会绕过该
   flow，任何首次出现且未关联的外部身份都会被拒绝；
7. 在两个 Realm 创建一个同名合成用户并预先创建精确 federated identity
   link；再创建一个只存在于上游 Realm 的合成用户；
   `trustEmail=false`、`storeToken=false`，不依靠邮箱自动关联或 JIT 猜测；
8. 用真实 HTML 表单完成：
   `OIDC Authorization + PKCE → SAML Broker → 上游登录 → SAML POST → OIDC code`；
9. 用正确的 `code_verifier` 完成 OIDC token exchange。

## 正向验收

测试直接检查协议文档和最终结果：

- AuthnRequest 带 XML Signature；
- SAML Response 带 XML Signature；
- SAML Assertion 带 XML Signature；
- `Audience` 精确等于 Broker Realm entity ID；
- Response `Destination` 精确等于 Broker ACS；
- SubjectConfirmationData `Recipient` 精确等于 Broker ACS；
- Response 与 SubjectConfirmationData 的 `InResponseTo` 都精确等于本次
  AuthnRequest ID；
- OIDC callback `state` 精确匹配；
- Authorization Code 使用 PKCE S256 成功换取 token。

双向签名不是只检查配置字符串：上游 SAML client 被设置为拒绝未签名的
AuthnRequest，下游 Broker 被设置为验证上游签名，且真实浏览器式流程必须在
这两个验证点都通过。

## 负向验收

测试包含三个真实拒绝路径：

1. **坏签名**：在已经签名的 SAML Response 中修改 NameID，保持原签名不变；
   Broker 返回 HTTP 400，并记录 `invalid_signature`。
2. **精确响应重放**：把同一份原始 `SAMLResponse` 和同一份 `RelayState`
   第一次提交至成功 callback 后，再原样提交一次；第二次返回 HTTP 400，并
   记录 `already_logged_in`。
3. **未知且未关联的外部身份**：使用只存在于上游 Realm 的第二个有效用户
   完成签名 SAML 登录；Broker 的 First Broker Login flow 返回 HTTP 401，
   不产生 OIDC code，并且测试前后的 Broker Realm 用户数完全不变。

第二项只证明 Keycloak 拒绝了已消费的 SP 发起登录会话和 RelayState 的精确
重放。它**不证明** Keycloak 26.7.0 提供通用的 Assertion-ID replay cache。
`<OneTimeUse/>` 条件在这里被生成并验证，但 Keycloak 该版本的
`ConditionsValidator` 只检查条件出现次数，不能据此宣称跨会话 Assertion
重放已被缓存拦截。生产方案若需要通用 Assertion-ID 防重放，必须单独设计并
验证有期限的 replay store。

参考：

- [Keycloak 26.7.0 First Broker Login 与禁用自动创建](https://www.keycloak.org/docs/26.7.0/server_admin/#disabling-automatic-user-creation)
- [Keycloak 26.7.0 Deny access authenticator](https://github.com/keycloak/keycloak/blob/26.7.0/services/src/main/java/org/keycloak/authentication/authenticators/access/DenyAccessAuthenticatorFactory.java)
- [Keycloak 26.7.0 ConditionsValidator](https://github.com/keycloak/keycloak/blob/26.7.0/saml-core/src/main/java/org/keycloak/saml/validators/ConditionsValidator.java#L211-L224)
- [Keycloak 26.7.0 SAML Endpoint validation](https://github.com/keycloak/keycloak/blob/26.7.0/services/src/main/java/org/keycloak/broker/saml/SAMLEndpoint.java#L585-L690)

## 隔离与清理

运行脚本会：

- 只监听随机的 `127.0.0.1` HTTPS 端口，并通过 `lsof` 拒绝非回环监听；
- 只允许测试进程访问唯一的
  `saml.c04-synthetic.example` origin，并固定解析到 `127.0.0.1`；
- 使用本次生成的自签证书，不信任公共 DNS 或系统 CA；
- 只在进程环境中传递随机 admin password 和合成用户 password；
- 不打印 token、密码、原始 SAML 文档或私钥；
- SAML XML 结构检查使用只返回布尔值的断言和固定错误消息，失败时不会把
  AuthnRequest、SAMLResponse 或 Assertion 写入 AssertionError；
- 无论成功、失败或被终止，都停止 Keycloak，并删除临时 H2、证书、私钥、
  日志和解压目录；
- 只可能保留已按 SHA-256 验证的公开 Keycloak tarball 缓存，不保留运行状态
  或秘密。

## 证据边界

该测试证明固定版本 Keycloak 在单机、两 Realm、合成数据条件下，能够重复
完成所列 SAML Broker 与 OIDC PKCE 协议路径。它不证明：

- 真实企业 IdP、AD/LDAP、SCIM 或企业用户已接入；
- IdP-initiated SSO 已获准或安全；
- 集群、高可用、外部数据库、密钥托管、证书轮换或灾备已经完成；
- 通用 Assertion-ID replay cache 已实现；
- 整个 C04 或整个 P1 已达到生产验收。

生产默认仍应使用 SP-initiated SSO、正式信任链、最小化属性映射、企业授权
的精确账号关联，以及独立审计和通用重放防护。
