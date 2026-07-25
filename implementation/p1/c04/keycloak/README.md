# C04 Keycloak 合成 OIDC 运行验证

状态：`RUNTIME_VERIFIED / SYNTHETIC_ONLY`

本目录固定 Keycloak 26.7.0 的 OIDC Authorization Code + PKCE S256 +
TOTP MFA 验证。`saml/` 另行记录 SAML Broker 黑盒路径，`scim/` 另行记录仍处于
Preview 的 SCIM Adapter 路径。三类证据必须分层引用，不能合并成“生产 IAM
已完成”。所有测试只使用运行时创建的 Synthetic Tenant、Synthetic User 和
`.example` 域名，不包含企业身份、企业 IdP、OA、U9 或 BI 信息。

## 运行

```sh
sh scripts/run-c04-keycloak-oidc-tests.sh
```

脚本会：

1. 按 `keycloak-distribution.lock.json` 验证 Keycloak tarball SHA-256；缓存不存在
   或校验不匹配时，才从锁定的 GitHub Release HTTPS 地址下载；
2. 使用 `mktemp` 创建一次性 Keycloak 安装、H2 数据、证书和日志目录；
3. 生成只在本次进程中存在的 bootstrap admin password、Synthetic User
   password 和 OIDC client secret；TOTP secret 由一次性 Keycloak 运行时生成，
   仅在测试进程和待清理的 H2 中存在；这些秘密均不打印或写入仓库；
4. 生成仅用于测试的自签名证书，以
   `https://idp.c04-synthetic.example:<random-port>` 启动 Keycloak，并只监听
   `127.0.0.1`；
5. 先完成一次性 TOTP 注册；随后用真实 HTML 表单验证“密码成功后仍必须提交
   OTP”，并证明缺少或提交错误 OTP 时不会获得 authorization code；
6. 为 Keycloak 浏览器流的密码和 OTP execution 配置 `pwd`、`otp` AMR 引用，
   要求签名 ID Token 同时包含二者，再映射为 C04 Core 的
   `authenticationMethods = ["amr:otp", "amr:pwd"]`；
7. 继续验证 state、PKCE、精确 issuer/audience/redirect、JWKS RS256 签名和
   authorization code 单次使用，再将 assertion 通过 `federationBroker` Port
   交给 C04 Core；
8. 无论成功、失败或收到终止信号，都停止 Keycloak 并清理一次性目录。

## 证据边界

该测试可以证明固定版本 Keycloak 的本机合成 OIDC 路径与当前 C04 Core Port
兼容，也能证明本次真实浏览器流执行了 password + TOTP 两个因子，而不是把
默认 `acr:1` 当作 MFA 证据。它不证明生产部署可用，不验证集群、高可用、
外部数据库、真实企业目录、恢复码或企业 MFA 策略，也不能证明 `saml/`、
`scim/` 的独立边界或把整个 C04 标记为 `VERIFIED`。

测试脚本不会信任系统 CA 或公共 DNS：TLS 使用本次生成的 CA 证书，所有
`idp.c04-synthetic.example` 连接由测试进程固定解析到 `127.0.0.1`。
