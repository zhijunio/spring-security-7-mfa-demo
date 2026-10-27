# Spring Security 7 MFA Demo

[![Java](https://img.shields.io/badge/Java-25-ED8B00?logo=openjdk&logoColor=white)](https://openjdk.org/projects/jdk/25/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.1.2-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-7.1.2-6DB33F?logo=springsecurity&logoColor=white)](https://spring.io/projects/spring-security)
[![Maven](https://img.shields.io/badge/Maven-3.10.0-C71A36?logo=apachemaven&logoColor=white)](https://maven.apache.org/)
[![License](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

简体中文 | [English](README.md)

这是一个基于 Spring Boot 4.1.2、Spring Security 7、Java 25 和 Maven 的浏览器两步认证示例。它展示 Spring Security 7 的 MFA 支持，并组合密码或 Passkey 主认证与 TOTP、开发用途邮件验证码、EIP-191 钱包签名或应用专用 BIP-39 助记词验证。项目使用内存账户和内存因子状态，不连接数据库。

> 仅供本地开发学习。演示账户、控制台邮件验证码和 relying-party 设置都不是生产方案，请勿部署到公网。

## 本地运行

需要 JDK 25：

```bash
./mvnw spring-boot:run
```

打开 <http://localhost:8080/>，使用演示账户 `demo` / `changeit`。应用状态存放在内存中，重启后清除。


## 认证流程与安全边界

主认证支持密码登录或 Spring Security WebAuthn Passkey assertion。主认证完成后，用户还需验证已启用的第二因子：TOTP、开发用途邮件验证码、EIP-191 钱包签名或应用专用 BIP-39 助记词。应用通过 `@EnableMultiFactorAuthentication(authorities = {})` 启用 Spring Security MFA 支持，再由应用级授权规则执行主认证加第二因子的流程；只有验证成功后，服务端才会授予因子 authority。MFA 状态保存在服务端 Spring Security session 中；请求体和自定义请求头不能授予角色或 MFA 状态。完成第二因子前，普通资源不可访问。Session 流程保留 CSRF 防护，写请求须提交 `GET /api/auth/csrf` 返回的 header 和 token。

因子管理、Passkey 注册和安全状态读取要求最近五分钟内完成 MFA。示例支持管理 TOTP、钱包签名和助记词因子，不提供一次性恢复码。示例实现两步验证流程，但不判断两个因子是否属于不同类别，也不校验 Passkey 是否执行了用户验证，因此并非所有组合都能满足严格的 MFA assurance 策略。API 拒绝响应使用 RFC 9457 `application/problem+json`。

## 接口契约

应用使用同源 HTTP 接口，API 请求体使用 JSON，并通过服务端 `JSESSIONID` 会话维持登录状态。先从 `GET /api/auth/csrf` 获取 CSRF token。主认证密码登录为 `POST /api/auth/login`，表单字段为 `username` 和 `password`；Passkey 登录使用 Spring Security WebAuthn 接口。主认证后，按需调用 `POST /api/auth/mfa/challenge` 获取 challenge（例如 `{"factorType":"EMAIL_OTP"}`），再向 `POST /api/auth/mfa/verify` 提交因子证明（例如 `{"factorType":"TOTP","proof":"123456"}`）。

| 方法与路径 | 契约 | 访问要求 |
| --- | --- | --- |
| `POST /api/auth/login` | 表单字段 `username`、`password` | 公开的主认证入口 |
| `POST /login/webauthn` | WebAuthn assertion JSON | 公开的 Passkey 主认证 |
| `POST /webauthn/authenticate/options` | 启动 Passkey assertion 流程 | 公开的主认证入口 |
| `GET /api/auth/csrf` | 返回后续写请求所需的 `headerName` 和 `token` | 公开引导接口 |
| `GET /api/auth/state` | 返回 `primaryAuthenticated`、`mfaComplete` 和 `username` | 公开引导接口 |
| `POST /api/auth/mfa/challenge` | JSON `{ "factorType": "EMAIL_OTP" }` 或 `WALLET_SIGNATURE`；TOTP、助记词和 WebAuthn 不需要单独 challenge | 已完成主认证 |
| `POST /api/auth/mfa/verify` | JSON `{ "factorType": "TOTP", "proof": "..." }`；也接受 `EMAIL_OTP`、`WALLET_SIGNATURE` 或 `BIP39_MNEMONIC` | 已完成主认证 |
| `GET /api/me` | 返回当前演示用户和受保护资源信息 | 主认证且 MFA 完成 |
| `GET /api/me/security` | 返回安全状态 | 五分钟内完成 MFA |
| `GET /api/mfa/factors` | 返回已注册因子 | 五分钟内完成 MFA |
| `DELETE /api/mfa/factors/{factorType}` | 移除 `TOTP`、`WALLET_SIGNATURE` 或 `BIP39_MNEMONIC`；返回 `204` | 五分钟内完成 MFA |
| `POST /api/mfa/totp/enroll` | 无请求体；返回 TOTP secret 和 `otpauthUri` | 五分钟内完成 MFA |
| `POST /api/mfa/totp/confirm` | JSON `{ "code": "123456" }` | 五分钟内完成 MFA |
| `POST /api/mfa/wallet/enroll` | JSON `{ "address": "0x..." }`；返回签名 challenge | 五分钟内完成 MFA |
| `POST /api/mfa/wallet/confirm` | JSON `{ "signature": "0x..." }` | 五分钟内完成 MFA |
| `POST /api/mfa/mnemonic/enroll` | 无请求体；返回只显示一次的应用助记词 | 五分钟内完成 MFA |
| `POST /webauthn/register/options`、`POST /webauthn/register` | WebAuthn 注册流程 | 五分钟内完成 MFA |
| `POST /logout` | 若当前 session 存在则将其注销 | 任意 session |

所有有状态变更的请求（包括登录和登出）都必须使用 `GET /api/auth/csrf` 返回的 header 名和 token，并保持同一 session cookie。无效或过期的因子证明及其他无效输入返回 `400`；移除未注册因子等状态冲突返回 `409`。未认证请求返回 `401`，认证阶段不足返回 `403`。这些错误响应使用 `application/problem+json`。OpenAPI 提供接口文档及可用的 schema，见 [OpenAPI JSON](http://localhost:8080/v3/api-docs) 与 [Swagger UI](http://localhost:8080/swagger-ui/index.html)。本地演示允许匿名查看这两个文档端点；生产环境应保护或关闭它们。

### 各因子

- **邮件验证码：** 只输出到本地日志；有效期五分钟、仅能使用一次，最多允许五次错误尝试，重新签发会替换旧码。生产环境须接入邮件服务、验证邮箱并实施限流。
- **TOTP：** 近期完成 MFA 后调用 `POST /api/mfa/totp/enroll` 获取 secret 与 `otpauth` URI，添加至认证器后调用 `POST /api/mfa/totp/confirm` 确认。验证允许 ±1 个 30 秒时间步，并拒绝已使用时间步的重放。生产环境应加密存储 secret。
- **Passkey：** 使用 Spring Security WebAuthn 注册和 assertion 登录；Passkey 主认证后仍需第二因子。示例 RP ID 为 `localhost`，允许 origin 为 `http://localhost:8080`，浏览器需运行于 localhost 或 HTTPS。
- **钱包签名：** 使用 web3j 校验 EIP-191 `personal_sign`，challenge 绑定账户与 session，并在成功后消费以防重放。演示域名、URI 和校验策略仅适用于本地。
- **BIP-39 助记词：** 应用使用 CSPRNG 生成 12 词应用凭据，仅在创建时显示一次，服务端存储 SHA-256 摘要。该凭据可重复用于 MFA，不是一次性恢复码。它是 bearer secret，不具备抗钓鱼能力。绝不要输入钱包或提交已有的钱包助记词；应用不会从该凭据派生密钥。

## 生产环境注意事项

生产系统还需持久化且访问受控的数据存储、加密 TOTP secret、持久化 WebAuthn 凭据、真实邮件服务、限流和审计、HTTPS 与安全 Cookie、正确的 RP ID/origin、SIWE 策略校验，以及因子撤销、恢复和凭据轮换流程。内存账户、演示密码、控制台 OTP、内存凭据存储和开发 RP 配置均不可直接用于生产。

## 许可证

本项目采用 Apache License 2.0。完整许可条款请参阅 [LICENSE](LICENSE)。
