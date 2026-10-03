---
name: 误报 / False positive
about: Watchdog 暂停了一个你认为正常的动作 / A normal action was paused
labels: false-positive
---

<!-- 请先脱敏：贴出的任何快照/证据片段必须已经过 redact 处理，并再人工检查一遍。 -->
<!-- Redact before pasting: snapshots are redacted automatically, but double-check. -->

## 发生了什么 / What happened

- 规则 ID（如 `sensitive-file-access`）/ Rule ID:
- 动作描述（模型想做什么）/ The action the model wanted to take:
- 为什么这是正常的 / Why this is legitimate:

## 环境 / Environment

- dsh 版本（`dsh -V`）/ DSH version:
- 操作系统 / OS:
- policy.json 中的相关配置（如有改动）/ Relevant policy.json settings:

## 建议 / Suggestion

- [ ] 这个误报可以通过 `allowed_hosts` / `allowed_paths` / `trusted_read_hosts` 配置解决
- [ ] 需要新的配置项或检测规则调整
- 其他建议 / Other suggestions:
