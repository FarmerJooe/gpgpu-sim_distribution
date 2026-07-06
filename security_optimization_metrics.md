# 安全内存优化指标说明

本文档说明用于分析 `common_syn` 和 `shm` 瓶颈的三个核心指标：Common Counter覆盖率、Read-only预测准确率和Streaming预测准确率。统计口径遵循Common Counter与SHM论文的方法，统计对象均为进入MEE的L2 miss和L2 writeback。

## 1. Common Counter覆盖率

Common Counter方法并不预测一个未经验证的counter值。它通过CCSM判断当前请求是否能够直接使用common counter。因此，这里使用论文中的覆盖率，而不是预测准确率。

对于每个需要counter的请求：

- 如果CCSM表明该地址能够由common counter服务，增加 `common_counter_served`；
- 否则请求普通CTR，增加 `normal_counter_served`；
- 写请求会使对应segment失去common状态，因此计入普通CTR请求。

覆盖率定义为：

$$
\text{CommonCounterCoverage}
=
\frac{N_{\text{common}}}
{N_{\text{common}}+N_{\text{normal}}}
$$

其中：

- $N_{\text{common}}$：由common counter直接服务的counter请求数；
- $N_{\text{normal}}$：仍需访问普通CTR的counter请求数。

未覆盖比例为：

$$
\text{UncoveredRatio}=1-\text{CommonCounterCoverage}
$$

该比例表示Common Counter无法消除、仍然可能引起CTR及BMT访存的请求比例。覆盖率越低，`common_syn`越依赖普通CTR路径，其性能瓶颈越明显。

对应输出：

```text
common_counter_served
normal_counter_served
common_counter_coverage
```

## 2. SHM Read-only预测准确率

Read-only predictor判断一个memory region能否使用共享counter，从而省略per-block CTR和BMT访问。

### 统计方法

1. 对每次L2 miss和L2 writeback记录read-only predictor给出的预测结果。
2. 同时记录每个region在整个统计区间内是否发生过writeback。
3. 模拟结束时，以完整访存记录作为offline profiling结果：
   - 没有发生writeback的region为read-only；
   - 发生过至少一次writeback的region为non-read-only。
4. 将每次访问时的预测结果与该region的offline profiling结果比较。

真实类别定义为：

$$
\text{ActualRO}(r)=
\begin{cases}
1, & N_{\text{writeback}}(r)=0\\
0, & N_{\text{writeback}}(r)>0
\end{cases}
$$

预测正确次数为：

$$
N_{\text{RO-correct}}
=
\sum_i
\mathbf{1}
\left[
\text{PredictedRO}_i=\text{ActualRO}(r_i)
\right]
$$

Read-only预测准确率为：

$$
\text{ROAccuracy}
=
\frac{N_{\text{RO-correct}}}
{N_{\text{RO-correct}}+N_{\text{RO-incorrect}}}
$$

统计按访问次数加权，而不是每个region只统计一次。访问频繁的region对最终准确率影响更大，这与其对性能和元数据流量的实际影响一致。

准确率越低，表示更多请求无法正确利用read-only属性，因而需要维护per-block CTR和BMT。

对应输出：

```text
read_only_prediction_correct
read_only_prediction_incorrect
read_only_prediction_accuracy
```

## 3. SHM Streaming预测准确率

Streaming predictor判断一个memory chunk应使用chunk-level MAC还是block-level MAC。准确率使用无限容量oracle MAT作为真实结果。

### 实际预测器

实际Streaming predictor使用有限数量的Memory Access Tracker（MAT）监控chunk的访问模式。有限MAT可能因为容量不足或访问模式变化而产生错误预测。

### Oracle MAT

Oracle MAT为每个活跃chunk分配独立tracker，因此没有MAT容量限制和替换冲突。除此之外，oracle与实际实现使用相同的检测规则：

- 每个monitoring phase最多观察32次访问；
- monitoring phase的超时时间为6000 cycle；
- 如果32个block均被访问，则该phase为streaming；
- 否则为random/non-streaming。

Oracle结果定义为：

$$
\text{OracleStreaming}(p)
=
\begin{cases}
1, & N_{\text{access}}(p)=32
\land N_{\text{unique-block}}(p)=32
\land \Delta T(p)\le 6000\\
0, & \text{otherwise}
\end{cases}
$$

对于phase中的每次L2 miss或L2 writeback，将访问发生时Streaming predictor的结果与该phase最终的oracle结果比较：

$$
N_{\text{stream-correct}}
=
\sum_i
\mathbf{1}
\left[
\text{PredictedStreaming}_i
=
\text{OracleStreaming}(p_i)
\right]
$$

Streaming预测准确率为：

$$
\text{StreamingAccuracy}
=
\frac{N_{\text{stream-correct}}}
{N_{\text{stream-correct}}+N_{\text{stream-incorrect}}}
$$

该指标同样按访问次数加权。准确率越低，表示更多访问采用了不合适的MAC粒度，造成block-level MAC流量无法消除，或者因错误预测产生额外MAC访问。

对应输出：

```text
streaming_prediction_correct
streaming_prediction_incorrect
streaming_prediction_accuracy
```

## 4. 三个指标与性能瓶颈的关系

三个指标分别描述不同优化的有效范围：

| 指标 | 对应优化 | 较低数值代表的瓶颈 |
|---|---|---|
| Common Counter覆盖率 | 使用common counter替代普通CTR | 更多请求仍需访问CTR和BMT |
| Read-only预测准确率 | 使用共享counter并省略freshness检查 | 更多请求仍需维护per-block CTR和BMT |
| Streaming预测准确率 | 使用chunk-level MAC | 更多block-level MAC流量或错误预测附加流量 |

因此，可使用以下逻辑解释实验结果：

1. `common_syn`的性能受Common Counter覆盖率限制，并额外承担CCSM和PAR流量；
2. `shm`的性能受Read-only和Streaming预测准确率限制，并保留未被优化的MAC流量；
3. `emcc`直接改善CTR表示和cache利用率，不要求程序呈现common、read-only或streaming特征，因此在这些指标较低的benchmark上更有优势。

