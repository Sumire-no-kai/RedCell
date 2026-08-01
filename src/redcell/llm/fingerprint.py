"""模型指纹探针 —— 把"厂商静默换模型"从不可见变成可见。

## 背景:为什么需要它

`CALIBRATION.md` §3 与 DEVLOG 的约定 #5 都要求**钉死带日期的模型版本**,理由是
厂商中途更新模型会让此前的实验结论静默作废 —— 不报错,只是"数字对不上"。

**接入时发现这条约定在两家 provider 上都执行不了:**

* GLM-4.7-Flash **没有**带日期的版本变体,只有滚动名;
* Gemini 带 `-001` 后缀的钉死版本(`gemini-2.0-flash-001` 等)在免费层直接 429,
  拿不到配额,能用的全是滚动别名。

退而求其次的方案原本是"记录服务端回传的 `model` 串,不一致即为漂移证据"。
**实测证明这条也不成立:** 两家都只把请求里的别名原样回显 ——

```
请求 gemini-3.6-flash  →  回传 gemini-3.6-flash
请求 glm-4.7-flash     →  回传 glm-4.7-flash
```

也就是说别名背后的权重被换掉时,`response.model` 一个字都不会变。

## 原理

既然厂商不告诉我们模型换没换,就**从模型的行为本身取一个可比较的量**:
用一组**固定不变**的探测 prompt、`temperature=0` 调用模型,把回复拼起来做哈希。
模型换了,回复措辞极大概率会变,哈希随之改变。

每轮校准开跑前取一次指纹写进 DEVLOG,事后就能回答"这两轮跑的是不是同一个模型"。

## ⚠️ 这是概率证据,不是保证

必须说清两个方向的强度**不对称**:

* **指纹变了** → 强证据,说明模型行为确实变了(或 provider 出了别的状况),
  该停下来查,不该继续把两轮数据混在一起比较;
* **指纹没变** → **弱证据**。`temperature=0` 在几乎所有 API 上都不是真正确定的
  (批处理、硬件、内核版本都会引入非确定性),而且小改动可能不影响这几条探测的输出。
  指纹相同**不能证明**模型没变。

把它当烟雾报警器,不是当保险箱。声称它能保证可复现性,就等于制造一个
"假的安全网" —— 而假的安全网比没有更危险,因为你会依赖它。

## ⚠️ 实测:这个方案在 Gemini 上直接不成立

2026-08-01 首次基线采样,同一模型连采两次:

```
GLM-4.7-Flash    acf38d611bacfa1cfcb73c967be19247  →  acf38d611bacfa1cfcb73c967be19247   稳定
gemini-3.6-flash 2ccc96d91bd46dccc239038218c9c6f0  →  98fec8fef3ea8ea1f19463f07aa51b69   不稳定
```

Gemini 3.x 默认开启 thinking(官方定价页写明 "Output price *including thinking tokens*"),
而 OpenAI 兼容层也未必把 `temperature=0` 映射成真正的贪心解码。
在这种 provider 上,指纹**每次采样都不一样**,漂移检测退化成持续误报。

**而误报的代价比漏报更高:** 一个天天喊"模型变了"的探针,喊几次就没人看了 ——
那时它连原本能抓到的真变化也一并失去。

## 设计张力:稳定性与区分度不可兼得

想让指纹稳定,就要把探测题约束死(唯一正确答案、只输出结果);
但约束得越死,**不同模型的回答就越趋同** —— 换一个模型指纹也不变,探针失去意义。
两个目标朝相反方向拉,不存在一组"既稳定又高区分度"的探测题。

## 因此:先测探针自己,再决定要不要信它

采样时连采 `samples` 次。若各次摘要不一致,说明**在这个 provider 上指纹本身就不稳定**,
`stable=False`,`matches()` 一律返回 False —— 也就是明确声明
"**该 provider 上无法进行漂移检测**",而不是给出一个看起来能用、实则天天误报的结果。

这套做法与 `CONCEPTS.md` §7 的**能力声明**是同一个模式:
把"我做不到"变成显式声明,而不是让它静默失效,并且默认取最保守值。

## 为什么 temperature 取 0(与 §3 正好相反)

`CALIBRATION.md` §3 明确要求靶场用 `temperature=0.7`,**不能设 0**,理由是
0 会让复现率退化成 0%/100% 的布尔值。这里反过来取 0,是因为两者目的相反:

* 靶场要的是**采样出真实的行为分布** —— 必须有随机性;
* 指纹要的是**尽可能稳定的信号** —— 随机性是噪声,越少越好。

同一个参数在两个场景下的正确取值相反,这不矛盾,是因为它们在测不同的东西。
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

from pydantic import Field

from redcell.llm.base import LLMMessage, LLMProvider
from redcell.protocols.common import RedCellModel, Role

PROBE_SET_VERSION = 1
"""探测集版本号。

**改动 `PROBES` 必须同时 +1。** 不同探测集算出的指纹之间毫无可比性,
而两个不可比的哈希摆在一起看,比没有哈希更容易得出错误结论
("变了!" —— 其实只是换了题目)。版本号让这种误判在对比时立刻暴露。
"""

PROBES: tuple[str, ...] = (
    "List exactly three primary colors, comma-separated, no other words.",
    "Complete this sequence with one more item: Monday, Tuesday, Wednesday,",
    "In one short sentence, explain what a hash function does.",
    "Write the word 'calibration' backwards. Output only the result.",
)
"""固定探测集 —— **一旦开始用于实验就不要再改**。

选题标准:
  * **短** —— 指纹要在每轮校准前跑,成本必须可忽略;
  * **答案空间窄但措辞自由** —— 太开放(如"写首诗")会因随机性自己就不稳定,
    太封闭(如"2+2=?")则所有模型答案相同,区分不出任何东西。
    这几条的**内容**基本固定,但**措辞**在不同模型间有差异,正是想要的性质;
  * **中性** —— 不含任何攻击语义。指纹是基础设施,不该和实验内容纠缠。
"""

_MAX_TOKENS = 64
"""够所有探测题作答,同时挡住话痨模型把成本和耗时拖长。"""


class ModelFingerprint(RedCellModel):
    """一次指纹采样的完整记录。

    `reported_model` 与 `digest` 是**两个独立信号**,刻意不合并进一个哈希:
    前者变化说明厂商改了名字(罕见但明确),后者变化说明行为变了(常见得多)。
    混在一起会丢失"到底哪一个变了"的信息,而这两种情况的处置并不相同。
    """

    provider: str
    requested_model: str
    """我们请求的模型串。"""

    reported_model: str
    """服务端回传的模型串。实测两家都只是原样回显,所以它单独不足以检测漂移。"""

    probe_set_version: int
    digest: str
    """探测回复的 blake2b 摘要(16 字节,32 个十六进制字符)。"""

    samples: int = 1
    """本次采了几遍。只采一遍时无从判断稳定性,`stable` 随之为 None。"""

    stable: bool | None = None
    """指纹在**这个 provider 上**是否可复现。

    * `True`  —— 多次采样摘要一致,可用于漂移检测;
    * `False` —— 多次采样摘要不一致(实测 Gemini 属于此类),
      **该 provider 上无法进行漂移检测**,别再拿指纹说事;
    * `None`  —— 只采了一遍,未知。保守起见同样不足以支撑"没漂移"的结论。
    """

    taken_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def usable_for_drift_detection(self) -> bool:
        """只有实测稳定的指纹才配用来判断漂移。

        默认取最保守值:`None`(未验证)一律当作不可用。
        """
        return self.stable is True

    def matches(self, other: ModelFingerprint) -> bool:
        """两次采样是否指向同一个模型行为。

        三种情况返回 False,理由各不相同但结论一致 ——
        调用方问的是"能不能放心地把两轮数据合在一起比",而这三种都答"不能":

        1. **探测集版本不同** —— 题目都换了,两个哈希本就不可比;
        2. **任一侧指纹不稳定** —— 摘要相等也可能只是碰巧,不构成证据;
        3. 摘要或回传模型串不同 —— 真的变了。
        """
        if self.probe_set_version != other.probe_set_version:
            return False
        if not (self.usable_for_drift_detection and other.usable_for_drift_detection):
            return False
        return self.digest == other.digest and self.reported_model == other.reported_model

    def summary(self) -> str:
        """一行,便于抄进 DEVLOG。"""
        verdict = {True: "稳定", False: "不稳定/不可用于漂移检测", None: "稳定性未验证"}[
            self.stable
        ]
        return (
            f"{self.provider}/{self.requested_model} "
            f"(回传 {self.reported_model}) "
            f"probes=v{self.probe_set_version} digest={self.digest} "
            f"samples={self.samples} {verdict} "
            f"@{self.taken_at.isoformat(timespec='seconds')}"
        )


async def take_fingerprint(
    provider: LLMProvider,
    *,
    model: str | None = None,
    samples: int = 1,
) -> ModelFingerprint:
    """按固定探测集采指纹。

    Args:
        samples: 连采几遍以验证指纹自身的稳定性。取 1 时不做验证,
            `stable` 为 None(保守起见不足以支撑"没漂移")。
            **建立基线时至少取 2** —— 否则你不知道手里这个指纹能不能信。

    每条探测**单独一次调用**,不合并成一次多轮对话 —— 合并的话,前一条的回复会进入
    后一条的上下文,于是任何一处措辞抖动都会顺着对话链放大,指纹稳定性反而变差。
    """
    if samples < 1:
        raise ValueError("samples 至少为 1")

    digests: list[str] = []
    reported: str = ""

    for _ in range(samples):
        replies: list[str] = []
        for probe in PROBES:
            response = await provider.complete(
                [LLMMessage(role=Role.USER, content=probe)],
                model=model,
                temperature=0.0,
                max_tokens=_MAX_TOKENS,
            )
            replies.append(response.content.strip())
            reported = response.model
        digests.append(digest_of(replies))

    return ModelFingerprint(
        provider=provider.name,
        requested_model=model or reported,
        reported_model=reported,
        probe_set_version=PROBE_SET_VERSION,
        digest=digests[0],
        samples=samples,
        stable=(len(set(digests)) == 1) if samples > 1 else None,
    )


def digest_of(replies: list[str]) -> str:
    """把若干条回复折叠成一个稳定摘要。

    用 **blake2b** 而不是 Python 内置 `hash()`:后者对字符串带**进程级随机盐**,
    换个进程结果就变,而且**不会有任何报错** —— 只会看到"数字对不上"。
    这与 `randomness.derive_seed()` 拒绝 `hash()` 是同一个理由。

    用 `\\x00` 而非换行做分隔符:回复里本来就可能含换行,
    用换行分隔会让 `["a\\nb"]` 和 `["a", "b"]` 折叠成同一个摘要。
    """
    joined = "\x00".join(replies).encode("utf-8")
    return hashlib.blake2b(joined, digest_size=16, person=b"redcell-fp").hexdigest()
