"""RedCell Arena —— 自带的、带 ground truth 的靶场。

这里的 agent 故意含有漏洞。它们是 benchmark 的基准答案:
每个 canary、每条权限约束、每个禁止工具都是已知的,
所以判定"攻击有没有成功"不需要 LLM 去猜,只需要确定性的匹配。
"""
