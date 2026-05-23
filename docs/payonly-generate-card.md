# PayOnly 随机卡生成功能

## 背景

默认情况下，PayOnly 流程从 `node-card.com` 的 verify 接口取真实卡信息。
开启本功能后，系统会在本地随机生成符合 Luhn 校验的 Visa 卡号，无需调用外部接口。

---

## 开关配置

在 `CTF-pay/config.paypal.json` 的 `payonly` 节点加两个字段：

```json
{
  "payonly": {
    "generate_card": true,
    "generate_address": true
  }
}
```

| 字段               | 类型    | 默认值  | 说明                                               |
|--------------------|---------|---------|---------------------------------------------------|
| `generate_card`    | boolean | `false` | 开启后跳过 node-card.com API，本地生成随机 Visa 卡 |
| `generate_address` | boolean | `false` | 开启后同时随机生成美国账单地址（需配合 `generate_card`） |

两个开关独立，组合效果如下：

| `generate_card` | `generate_address` | 效果                                    |
|-----------------|--------------------|-----------------------------------------|
| `false`         | —                  | 走原有 node-card.com verify 接口（默认）|
| `true`          | `false`            | 随机 Visa 卡号，地址继承 `cards[0]` 配置 |
| `true`          | `true`             | 卡号 + 地址全部随机生成                  |

---

## 生成规则

### Visa 卡号

- 前缀从以下 BIN 随机选一个：`4539` `4556` `4916` `4532` `4929` `4485` `4716` `4024` `4508`
- 前缀后接 11 位随机数字，共 15 位
- 第 16 位（校验位）由 **Luhn 算法**反推生成，保证号码合法

### CVV

- 3 位随机数字，范围 `100–999`

### 到期日

- 月份：1–12 随机
- 年份：当前年 + 2~4 年（确保未过期，但也不会太远）
- 格式：`MM/YY`（如 `03/28`）

### 持卡人姓名

- 从内置英文名字库随机组合（名 + 姓），全大写
- 示例：`JAMES WILLIAMS`、`SARAH MARTINEZ`

### 账单地址（`generate_address: true` 时）

- 城市/州/邮编三字段绑定随机，取自内置 15 组真实美国城市数据
- 门牌号 100–9999 随机，街道名从内置 20 条随机选
- 国家固定 `US`

---

## 缓存行为

与从 API 取卡一致：**首次生成后写入 DB 缓存，同一账号后续重试直接读缓存**，不会每次生成不同的卡。

缓存记录包含以下字段（可在 `/api/inventory/standalone/payonly/cache/{account_id}` 查看）：

```json
{
  "account_id": 123,
  "email": "user@example.com",
  "assigned_at": "2026-05-22T10:00:00+00:00",
  "verify_url": "generated",
  "verify_body": null,
  "verify_response": null,
  "card_info": {
    "card_number": "4916xxxxxxxxxx07",
    "expiry_date": "03/28",
    "cvv": "471",
    "name": "JAMES WILLIAMS",
    "phone": "",
    "sms_api": "",
    "address": {
      "line1": "1234 Oak Ave",
      "city": "Chicago",
      "state": "IL",
      "postal_code": "60601",
      "country": "US"
    }
  }
}
```

`verify_url: "generated"` 可用于区分是本地生成还是 API 取回的卡。

---

## 代码位置

| 内容           | 文件                                        | 位置               |
|----------------|---------------------------------------------|--------------------|
| 数据表 + 生成函数 | `webui/backend/routes/inventory.py`        | `_payonly_gen_*` 系列函数 |
| 取卡入口（含开关判断） | `webui/backend/routes/inventory.py` | `_payonly_card_for_account()` |
| 脚本流接入     | `webui/backend/routes/inventory.py`         | `_run_payonly_script_for_account()` |

---

## 注意事项

- **随机卡不能真实扣款**，仅适用于测试环境或对卡号真实性无要求的场景
- `generate_address: false` 时地址来自 `cards[0].address`，若该字段为空则下游使用默认值
- 开关变更后新账号生效，已缓存的账号（有 `card_info` 缓存）不受影响；如需重新生成，需先清除对应账号缓存
