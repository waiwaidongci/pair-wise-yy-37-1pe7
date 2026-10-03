# 空气污染源许可与合规检查

管理设施、排放口、治理设备、现场检查、整改和许可续期。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8314
```

默认端口为`8314`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `POST /api/items/{id}/renewal`，许可续期交接，必须提交`renewal_no`和`expected_version`
- `GET /api/items/{id}/renewals`，续期台账与冲突留档
- `GET /api/audit`

允许角色：applicant, inspector, compliance_manager, viewer。申报量超过许可量或检查发现高严重度问题时提高优先级；存在未关闭整改时不能批准。

## 许可续期交接

仅`compliance_manager`可对`approved`状态的许可发起续期。续期交接是一次可回滚事务，整笔完成：冻结旧额度、登记现场检查、关闭未结整改、签发续期新许可（`approved`、额度`active`、通过`renewal_of`/`renewal_no`关联旧许可）、停用旧额度（`quota_status`变为`deactivated`）。任一步失败整笔回滚到原状态，可按原`renewal_no`重试。

- 同一`renewal_no`同人同内容重复提交：只认第一次，返回首次结果（HTTP 200，`idempotent: true`）。
- 同一`renewal_no`内容不同：主事务不生效，冲突单独写入`renewal_conflicts`留档并审计。
- 两位审核人同时提交同一续期：接纳先到的一笔，另一位拿到版本冲突原因（HTTP 409）。
- 许可升级时自动为旧数据补列并补写`baseline`历史基线记录，重复执行安全。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
