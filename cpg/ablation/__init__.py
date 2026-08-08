"""三模式上下文消融实验后端包。

本包为科研消融骨架，不依赖任何产品级框架。所有 CodeQL 调用均复制自
``cpg/pipeline.py`` 已验证的命令与 bqrs 解码逻辑（见 config.py 中的 run / win_path /
make_env / _csv_has_rows / _is_defender_block），不重新实现 CPG 提取。

包内模块均以绝对导入 ``from cpg.ablation import X`` 组织；每个可执行脚本在顶部把仓库根
加入 ``sys.path``，因此既可用 ``python3 cpg/ablation/run_ablation.py`` 直接运行，也可用
``python -m cpg.ablation.run_ablation`` 运行。
"""

from . import config  # noqa: F401  (re-export共享常量，方便 from cpg.ablation import config)

__all__ = ["config"]
