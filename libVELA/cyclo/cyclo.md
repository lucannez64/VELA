

# Cyclo: Lightweight Lattice-based Folding via Partial Range Checks

Albert Garreta<sup>1</sup>, Helger Lipmaa<sup>2</sup>, Urmas Luhaäär<sup>2</sup>, and Michał Osadnik<sup>3</sup>

<sup>1</sup> Nethermind Research [albert@nethermind.io](mailto:albert@nethermind.io)

<sup>2</sup> University of Tartu, Estonia [helger.lipmaa,urx}@ut.ee](mailto:{helger.lipmaa,urx}@ut.ee)

<sup>3</sup> Aalto University, Finland [michal.osadnik@aalto.fi](mailto:michal.osadnik@aalto.fi)

**Abstract.** Folding is a powerful technique for constructing efficient succinct proof systems, especially for computations that are expressed in a streaming fashion. In this work, we present Cyclo, a new lattice-based folding protocol that improves upon LatticeFold+ [Boneh and Chen '25] in multiple dimensions and which incorporates, among others, the pay-per-bit techniques from Neo when folding constraints expressed over a field  $\mathbb{F}_q$  [Nguyen and Setty '25]. Cyclo proposes a new framework for building lattice-based folding schemes that eliminates the need for norm checks *on the accumulator* by adopting an amortized norm-refreshing design, ensuring that the witness norm grows additively per round within a (generously) bounded number of folds. This design simplifies the protocol and reduces prover overhead. In particular, Cyclo only performs range checks on the input *non-accumulated* witness, and when applied to fold constraints over  $\mathbb{F}_q$ , it does not decompose any witnesses into low-norm chunks within the folding protocol itself. Cyclo, supporting a complete family of cyclotomic rings, combines two simple building blocks: an extension commitment that reduces the norm of the witness by decomposing it and recommitting, and an  $\ell_\infty$  range test via a sum-check protocol. We demonstrate, by proving communication and runtime estimates that the construction results in an efficient and proof-size-friendly folding scheme. We also establish an algebraic connection between  $\mathcal{R}_q$  and  $\mathbb{F}_q$  using the polynomial evaluation map, enabling efficient reduction from R1CS/CCS over  $\mathbb{F}_q$  to a linear relation over  $\mathcal{R}_q$ , providing a new and simpler formulation of the techniques in [Nguyen and Setty '25]. In practical settings, Cyclo achieves succinct proof sizes on the order of 30 KB, improving by an order of magnitude over LatticeFold+. Our efficiency benchmarks indicate that our protocol also outperforms LatticeFold+ in practice.

# Table of Contents

|     |                                                                                                                          |    |
|-----|--------------------------------------------------------------------------------------------------------------------------|----|
| 1   | Introduction . . . . .                                                                                                   | 2  |
| 1.1 | Our contributions . . . . .                                                                                              | 4  |
| 2   | Technical Overview . . . . .                                                                                             | 6  |
| 2.1 | LatticeFold(+) Framework for Folding Linear Relations . . . . .                                                          | 7  |
| 2.2 | New Framework: Amortized Norm-Refreshing Folding Scheme . . . . .                                                        | 8  |
| 2.3 | Building Blocks of Cyclo . . . . .                                                                                       | 9  |
| 2.4 | Cyclo: Putting the Building Blocks Together . . . . .                                                                    | 10 |
| 2.5 | Norm growth: completeness and soundness . . . . .                                                                        | 10 |
| 2.6 | From R1CS over $\mathbb{F}_q$ to the Principal Linear Relation . . . . .                                                 | 11 |
| 2.7 | Concrete Efficiency of the Folding Scheme . . . . .                                                                      | 13 |
| 3   | Preliminaries . . . . .                                                                                                  | 14 |
| 4   | Range Test . . . . .                                                                                                     | 17 |
| 5   | Extension Commitment . . . . .                                                                                           | 18 |
| 6   | Folding Scheme: Cyclo . . . . .                                                                                          | 20 |
| 6.1 | Parameters Selection and Efficiency Estimates . . . . .                                                                  | 23 |
| 7   | R1CS/CCS over $\mathbb{F}_q$ to the principal linear relation . . . . .                                                  | 24 |
| 7.1 | A low-norm, bit-size preserving encoding of $\mathbb{F}_q$ in $\mathcal{R}_q$ via module homomorphic preimages . . . . . | 24 |

|     |                                                                                                    |    |
|-----|----------------------------------------------------------------------------------------------------|----|
| 7.2 | Reduction to the committed hybrid R1CS relation . . . . .                                          | 25 |
| 7.3 | Reduction to the principal linear relation . . . . .                                               | 26 |
| A   | Extended Preliminaries . . . . .                                                                   | 32 |
| A.1 | Variants of Principal Linear Relation . . . . .                                                    | 32 |
| A.2 | SIS-break Relation . . . . .                                                                       | 33 |
| A.3 | Reduction of Knowledge . . . . .                                                                   | 33 |
| B   | Instantiation of Strong Sampling Set . . . . .                                                     | 34 |
| B.1 | Exact Strong Sampling Set . . . . .                                                                | 34 |
| B.2 | Approximate Strong Sampling Set . . . . .                                                          | 35 |
| C   | Parameters Selection and Practical Evaluation . . . . .                                            | 36 |
| C.1 | Communication . . . . .                                                                            | 37 |
| C.2 | Benchmark of the Extension Commitment and Comparison with Double Commitment from [BC25b] . . . . . | 38 |
| C.3 | On the efficiency of Sum-check . . . . .                                                           | 39 |
| C.4 | Memory usage . . . . .                                                                             | 40 |

# 1 Introduction

In recent years, succinct non-interactive arguments of knowledge (SNARKs) have become central to applications such as blockchains [XZC<sup>+</sup>22,GKO24,LM25,LZW<sup>+</sup>25], privacy-preserving authentication [EHRS24], and verifiable computation [ACGS24,CCC<sup>+</sup>25]. Despite their power, SNARKs suffer from a major memory bottleneck that limits their applicability[LZW<sup>+</sup>24,ZSCZ25]: the prover must load the entire computation into memory. This is infeasible for large computations and, more broadly, fails to capture how computations are often carried out in practice, namely in a streaming manner.

This setting, motivated in particular by practical applications such as blockchains and verifiable outsourced computation (e.g., cloud/edge ML inference and long-running services), has led to the framework of *incrementally verifiable computation* (IVC) [Val08,NPR19] and its generalization, proof-carrying data [CT10,BCL<sup>+</sup>21,BDFG21,CCG<sup>+</sup>23]. Early IVC protocols were built from SNARKs and can be viewed as producing, at each step, a proof for the computation performed by the verifier in the previous step [Val08,BCCT12,BCTV14]. More modern approaches use *folding schemes* [BGH19,BDFG21,BCL<sup>+</sup>21,BC25a,BC25b], which let the prover aggregate many computation steps into a single instance of an accumulator relation. This is substantially simpler than proving the entire computation at each step and yields improved efficiency.

Folding can be understood via reductions of knowledge [ACK21,KP22]. A reduction of knowledge from a relation  $\Xi_0$  to a relation  $\Xi_1$  is a protocol  $\Pi$  between a prover and a verifier in which the verifier, given an instance  $x_0$  for  $\Xi_0$ , interacts with the prover and ultimately outputs an instance  $x_1$  for  $\Xi_1$ . The key property is that if the prover can provide a witness  $w_1$  for  $x_1$ , then one can extract a witness  $w_0$  for  $x_0$  from the prover. A folding scheme realizes a reduction of knowledge from the product relation  $\Xi_{acc} \times \Xi_0$  to the accumulation relation  $\Xi_{acc}$ : it folds a pair of instances  $(x_{acc}, x_0)$  into a single new instance  $x'_{acc}$  of  $\Xi_{acc}$ . Repeating this reduction lets the prover aggregate many computation steps (expressed by  $\Xi_0$ ) into a single instance of the accumulator relation  $\Xi_{acc}$ . This intuition also extends naturally to multiple-input relations, allowing folding with inputs from  $\Xi_{acc} \times (\Xi_0 \times \dots \times \Xi_{d-1})$ .

The best-established folding schemes rely on linearly homomorphic commitments, such as Pedersen commitments [Ped92], to commit to the witness of the input relation. Folding then amounts

to combining the per-step commitments into a single commitment to the folded instance. Unfortunately, Pedersen relies on the discrete logarithm assumption and is therefore vulnerable to quantum attacks [Sho94]. A compelling alternative is the Ajtai commitment [Ajt96], which is based on the hardness of lattice problems and is widely viewed as post-quantum secure; we discuss lattice-based folding schemes below. Another line of work builds folding schemes from hash-based commitments and error-correcting codes [BMNW25a,BCFW25,BMNW25b].

**Lattice-based folding schemes.** The best-established folding schemes rely on linearly homomorphic commitments, such as Pedersen commitments [Ped92], to commit to the witness of the input relation. Folding then amounts to combining the per-step commitments into a single commitment to the folded instance. A major recent advance is the development of lattice-based folding schemes, including Lova [FKNP24], LatticeFold [BC25a], LatticeFold+ [BC25b], and Neo [NS25]. These schemes replace Pedersen commitments with plausibly quantum-secure Ajtai commitments, yielding plausible post-quantum security. However, translating Pedersen-based folding to the lattice setting is not straightforward: Ajtai commitments critically depend on the committed message being short, i.e., the witness having low norm. This shortness constraint creates difficulties because the witness norm typically grows with each folding step. Moreover, norm growth arises not only in folding (the “correctness direction”), but also in extraction (the “extraction direction”), when recovering a witness for the input relation from a witness for the folded relation. This growth complicates the soundness analysis, since one must ensure that the witness norm stays within acceptable bounds throughout folding.

To address the norm growth issues, prior lattice-based folding schemes combine two general techniques, which are afterward instantiated differently in each folding scheme:

- *Decomposition.* Given a witness vector of norm at most  $B$ , this procedure decomposes it into chunks of smaller norm  $b$ . The chunks are later randomly combined using low-norm verifier challenges so that the resulting linear combination has norm at most  $B$ . This step is needed for completeness, i.e., to ensure the accumulated output witness remains low-norm.
- *Range-check.* These are variants of range proofs that certify a witness vector satisfies a prescribed bound. This step is needed for soundness, ensuring that extractors output low-norm witness vectors.

Under this lens, LatticeFold and LatticeFold+ exhibit the following cost profiles. LatticeFold uses grand-product-sum-based range-checks for very small bounds (e.g.,  $b = 2$ ). A single such range check, as we show in this work, is efficient. However, during decomposition, LatticeFold splits each input witness into  $k$  low-norm chunks, commits to them, and then applies a sum-check-based range-check to each chunk (the sum-checks are batched, but prover time still grows linearly in  $2k$ ); hence the overall combined procedure is relatively expensive, cf. [Res24]. In contrast, LatticeFold+ uses a very lightweight decomposition step (it decomposes into only 2 vectors).

The most efficient instantiations of lattice-based primitives use cyclotomic rings of the form  $\mathcal{R} = \mathbb{Z}[X]/\langle\Phi_f(X)\rangle$ , where  $\Phi_f(X)$  is the  $f$ -th cyclotomic polynomial. Over  $\mathcal{R}$ , the LatticeFold+ range-check (which computes so-called *double-commitments*) is relatively costly: it requires computing at least  $\varphi$  (the ring degree) “single” Ajtai commitments and then re-committing to them. A cheap grand-product sum-check-based range-check is unavailable here because the verified norm bound  $B$  is not small enough. Other norm checks (tailored to the  $\ell_2$ -norm) have been used in lattice-based argument systems [BS23,KLNO24,KLNO25b] and transfer almost directly to the folding setting.

**Lattice-based folding schemes for constraints expressed over finite fields.** The ring  $\mathcal{R}$  admits a natural embedding into  $\mathbb{Z}^{\varphi(f)}$ , where  $\varphi$  is Euler’s totient function. However, in many

cryptographic protocols, relations are defined over finite fields  $\mathbb{F}_q$ . Thus, using cyclotomic rings in such protocols requires translating relations from  $\mathbb{F}_q$  to  $\mathcal{R}_q = \mathcal{R}/q\mathcal{R}$ . This translation is nontrivial: one must preserve the algebraic structure of the original relation in the ring setting. Moreover,  $\mathbb{F}_q$ -based relations (e.g., R1CS or CCS) typically omit norm constraints, which are essential for lattice-based security. Accordingly, the translation must also include an appropriate decomposition so that the resulting relation over  $\mathcal{R}_q$  is compatible with Ajtai commitments.

A natural idea is to use the Number Theoretic Transform (NTT), which provides a ring isomorphism  $\mathcal{R}_q \cong \mathbb{F}_q^{\varphi(f)}$  (when  $q$  splits  $\Phi_f(X)$  completely), mapping each ring element to its evaluations at the roots of  $\Phi_f(X)$ . Each coordinate of this embedding lies in  $\mathbb{F}_q$ , so one can encode field elements into individual “slots” of a ring element. For example, consider the cyclotomic ring  $\mathbb{Z}[X]/\langle X^4 + 1 \rangle$  with  $q = 17$ . Since  $X^4 + 1$  splits completely modulo 17 as  $(X - 2)(X - 4)(X - 8)(X - 15)$ , the Chinese Remainder Theorem gives an isomorphism  $\mathcal{R}_q \cong \mathbb{F}_{17}^4$ , mapping a polynomial  $f(X)$  to its evaluations  $(f(2), f(4), f(8), f(15))$ . Thus, four field elements  $a_0, a_1, a_2, a_3 \in \mathbb{F}_{17}$  can be “packed” into one ring element by finding the unique polynomial  $f(X) \in \mathcal{R}_q$  satisfying  $f(2) = a_0$ ,  $f(4) = a_1$ ,  $f(8) = a_2$ ,  $f(15) = a_3$ . Nevertheless, this approach faces several challenges: (1) The NTT embedding is useful only when the relation can be “packed” into slots, which typically requires working with multiple instances of the relation. This is not always possible. Otherwise, the embedding can impose substantial overhead, since the relation must be expanded to fill the slots, increasing complexity. (2) Even if the  $\mathbb{F}_q$  witness has small norm, there is no guarantee that the corresponding witness over  $\mathcal{R}_q$  does, which is crucial both for the security of Ajtai commitments and for the efficiency of the commitment step. Hence, the  $\mathcal{R}_q$  relation must be further decomposed to enforce norm bounds. This decomposition can be intricate and may inflate proofs and computation, potentially offsetting any gains from packing multiple field elements into one ring element. (3) Naively encoding  $\mathbb{F}_q$ -native relations over  $\mathcal{R}_q$  forces the folding scheme to operate over  $\mathcal{R}_q$ . This can be wasteful: operations in  $\mathcal{R}_q$  are far more expensive than in  $\mathbb{F}_q$ , and ring elements are much larger than field elements. It is therefore desirable to minimize computation over  $\mathcal{R}_q$ . (4) The NTT embedding requires a modulus  $q$  that splits the cyclotomic polynomial  $\Phi_f(X)$ , which can severely restrict parameter choices and may be impractical. Worse, this splitting condition can conflict with other requirements, such as invertibility of small-norm elements [LS18, ACX19, BS23] or the existence of large subfields [KLNO24].

To overcome these challenges, Nguyen and Setty (Neo, [NS25]) propose a translation from  $\mathbb{F}_q$ -based relations to  $\mathcal{R}_q$ -based relations that does not rely on the NTT embedding. Neo encodes a field element  $c \in \mathbb{F}_q$  as a ring element  $p_c(X) \in \mathcal{R}_q$  whose coefficients are the base- $b$  decomposition of  $c$ , for a suitable  $b$ . This resolves issues 1, 2, and 4 above. In addition, Neo performs one folding step (analogous to the linearization step in Hypernova [KS24]) entirely over  $\mathbb{F}_q$ , rather than over  $\mathcal{R}_q$ , where prover time would be substantially higher. This addresses issue 3.

Although powerful, Neo [NS25] introduces fairly complex, ad hoc machinery and terminology (e.g., matrix commitments and commutative subrings of matrices in place of standard ring-based constructions). Building on Neo’s key ideas, we show that the same translation from  $\mathbb{F}_q$ -based to  $\mathcal{R}_q$ -based relations can be achieved within a simpler framework that works exclusively with cyclotomic rings, finite fields, and standard linear maps, yielding a more accessible and modular construction.

## 1.1 Our contributions

With this work, we make the following contributions:

**No decomposition and range-check for input accumulated witnesses.** As we mentioned, all current lattice-based folding schemes from  $\Xi_{acc} \times \Xi_0$  to  $\Xi_{acc}$  use range-checks to make sure that

the norm of the accumulated instances stays within some specified bound  $B$ . This range-check is ultimately applied to both the input witness from the relation  $\Xi_0$  and the input witness from the accumulated relation  $\Xi_{acc}$ . In this work *we make the key observation that, if one omits the latter range-check, then one can ensure that the norm growth of the output accumulated witness only grows by a small additive factor* (see Section 2.5 in the technical overview for more details).

Consequently, we can perform folding without applying any decomposition or range-check to the input witness from  $\Xi_{acc}$ , at the expense of not being able to perform arbitrarily many foldings: indeed, at each folding step, the norm grows by a small additive factor, and so after a certain finite number  $\ell_{\text{fold}}$  of folds, the scheme stops being sound. We instantiate our scheme with  $\ell_{\text{fold}}$  ranging from  $2^7$  to  $2^{20}$ , which we believe is enough for overwhelmingly many applications. In addition, one can use a different folding scheme, say LatticeFold+, once every  $\ell_{\text{fold}}$  folding steps to “refresh” the norm of the accumulated witness.

**No witness decomposition when folding R1CS/CCS constraints over a finite field  $\mathbb{F}_q$  with an accumulated instance.** As we discuss later, when seeking to apply our folding scheme on R1CS/CCS constraints over  $\mathbb{F}_q$ , we encode witnesses as cyclotomic ring elements of very low norm  $b$  (say,  $b = 2$ ), as done in Neo [NS25]. Thus, the input witness from  $\Xi_0$  does not require any “decomposition,” unlike those mentioned earlier. In this specific setting, thanks to our key observation, we can perform (a bounded number of) foldings by only range-checking the input witness from  $\Xi_0$ , and then folding with the input accumulated witness. In particular: (1) no decomposition step is ever applied to any witness, (2) range-check is only applied to the input witness from  $\Xi_0$ , and (3) folding is performed in a standard manner between the range-checked input witness from  $\Xi_0$  and the input accumulated witness. This avoids the most expensive steps of LatticeFold+, Neo, and LatticeFold, namely the double commitment for the first two and the decomposition into chunks and range-checking for every chunk in the latter. Ultimately, our scheme only requires two non-batched<sup>4</sup> sum-checks over an extension of  $\mathbb{F}_q$  for  $\log(m\varphi)$ -variate low-degree polynomials. Here,  $m$  is the length of the packed witness  $\mathbf{w} \in \mathcal{R}_q^m$  in ring elements.

*Remark 1.* We stress that the above efficiency gains refer to the folding protocol itself, without considering the overhead of recursive verification (i.e., in-circuit verification of the folding scheme). In the recursive setting, the benefit analysis is more nuanced. Encoding field elements as low-norm polynomials in  $\mathcal{R}_q$  may increase the witness representation size, since each  $\mathbb{F}_q$  element is represented as a ring element of potentially larger bit-length. However, the verifier does not operate on the witness directly, and the absence of decomposition and extension commitment steps means that the verifier performs fewer operations throughout the scheme. Therefore, the recursion circuit can still be significantly smaller than in folding schemes that require decomposition and double commitment. This advantage is further amplified if Cyclo is (trivially) modified so that the public instance  $\mathbf{x}$  (which does appear in the verifier’s circuit) is kept outside the Ajtai commitment and can thus be represented as a vector of field elements rather than ring elements.

**A new take on witness decomposition + range-check.** The fact that we do not need to apply any decomposition or range-check to the input accumulated witness has yet another consequence for us. Namely, we can design a new “decomposition + range-check step” using a technique we call *extension commitment* (see the technical overview for more details). As we demonstrate, extension

<sup>4</sup> Some folding schemes, like LatticeFold, batch many sum-checks, say  $k$ , into one, which effectively increases the prover time linearly in  $k$ . In LatticeFold in particular,  $k$  is the number of chunks produced in the decomposition step

commitments can be an order of magnitude more efficient than LatticeFold+’s double commitments. Our extension commitment is then followed by a simple sum-check-based range-check, which, as we mentioned, is cheap when one does not need to batch many of them, which is our case.

We emphasize that this technique is not usable in a setting where one must apply decomposition and range-checking to the accumulated input witness. Hence, our aforementioned key observation enables simpler approaches to the decomposition and range-check steps.

**Parameter and efficiency improvements.** Our folding scheme is efficient and memory-friendly, i.e., we obtain numbers which are orders of magnitude smaller than those from [BC25b]. (See Section 6.1.) In particular, we show that the folding proofs are around 30 KB for practical parameters, which is an order of magnitude smaller than those of LatticeFold+.

We provide efficiency estimates concerning the most computationally expensive part of our folding scheme, i.e., the extension commitment. We also provide an evaluation of the corresponding part of LatticeFold+ [BC25b], i.e., double commitment, for comparison.

**Bit-size preserving embedding of  $\mathbb{F}_q$  into  $\mathcal{R}_q$  via homomorphic preimages, and reduction from R1CS relations over  $\mathbb{F}_q$  to linear relations over  $\mathcal{R}_q$ .** As we mentioned, Neo’s approach to folding R1CS/CCS constraints over  $\mathbb{F}_q$  relies on relatively non-standard terminology and techniques. Building on Neo’s ideas, we reformulate them in terms of cyclotomic rings, finite fields, and linear maps, resulting in a construction that requires only standard algebraic tools and no specialized matrix-algebraic machinery. Crucially, we observe that Neo can be understood as a scheme that works in a hybrid manner over  $\mathcal{R}_q$  and  $\mathbb{F}_q$ , and which relies on the additive homomorphism  $\theta_b : \mathcal{R}_q \rightarrow \mathbb{F}_q$  where  $\theta_b(f(X)) = f(b)$  to link both structures.

We emphasize that Neo’s and our approaches are ultimately equivalent. However, we believe this equivalence is far from obvious, and that our simple algebraic viewpoint suggests a general framework for integrating lattice-based cryptography in modern proof systems: namely, to use  $\mathcal{R}_q$  solely for commitment purposes, and work otherwise on the base field (or different rings) of interest, using a morphism to link both structures.

**An approximately strong sampling set over NTT-friendly cyclotomics.** As a side contribution, we provide a heuristic analysis of the ternary distribution (i.e., sampling coefficients uniformly from  $\{-1, 0, 1\}$ ) as an approximate strong sampling set, which is of independent interest. Our analysis allows the use of more NTT-friendly cyclotomic rings (e.g., splitting down to quadratic extension fields with a modulus that fits into a machine word). The results apply to other contexts where strong sampling sets are needed, e.g., in lattice-based argument systems [BS23, KLNO25b] and could be viewed as a statistical alternative to the analysis of [LS18, ACX19], offering more flexibility in the choice of parameters.

# 2 Technical Overview

Throughout this work, we assume that  $\mathcal{R}$  is a cyclotomic ring and  $\mathbb{Z}_q = \mathbb{Z}/q\mathbb{Z}$ . For simplicity of exposition, solely in the overview we assume  $\mathcal{R} := \mathbb{Z}[X]/\langle X^\varphi + 1 \rangle$ , where  $\varphi$  is a power-of-two. Let  $\text{ct}$  be the map that takes a ring element to its constant term. Let  $\mathcal{R}_q := \mathcal{R}/q\mathcal{R}$  for a prime  $q$ . Let  $\text{cf}$  be the map that takes a ring element to its coefficient vector in  $\mathbb{Z}^\varphi$ . Let  $\text{cf}^{-1}$  be its inverse map  $\mathbb{Z}^\varphi \rightarrow \mathcal{R}$ . Furthermore, we define a map  $\text{cf}_\vee$  (together with its inverse) as  $\text{cf}_\vee(a) = (a_i^\vee)_{i \in [\varphi]}$ , where  $a \in \mathcal{R}$  and the coefficients of  $a$  are  $(a_0, \dots, a_{\varphi-1})$ , and  $a_i^\vee := a_i$  if  $i = 0$ , and  $a_i^\vee := -a_{\varphi-i}$  otherwise. Clearly,  $\text{ct}(a \cdot b) = \langle \text{cf}(a), \text{cf}_\vee(b) \rangle$  for any  $a, b \in \mathcal{R}$ , where  $\langle \cdot, \cdot \rangle$  denotes the inner product. This

will be generalized to the complete family of cyclotomic rings in the paper, by replacing  $\mathbf{ct}$  with the algebraic trace and formalizing  $\mathbf{cf}_\vee$  as an embedding over the dual basis of structured  $q$ -ary lattices. We denote  $\|\cdot\|$  to be the infinity norm on vectors (w.r.t. the coefficient basis). In this overview, we conveniently assume that the folding scheme considers a single input relation and leave the (almost straightforward) generalization to multiple input relations for the body of the paper.

## 2.1 LatticeFold(+) Framework for Folding Linear Relations

LatticeFold [BC25a] and LatticeFold+ [BC25b], although significantly different in their technical details, share a common framework. We briefly review the framework here to set up the context for our technical contributions. For fixed  $\mathbf{p} := (\mathcal{R}, a, n, m, q, B)$ , and  $\mathbf{F} \in \mathcal{R}_q^{a \times m}$ , consider the following linear relation:

$$\Xi_{\mathbf{F}}^{\text{lin}} := \{ \underline{\mathbf{y}}, \underline{\mathbf{w}} : \mathbf{y} \in \mathcal{R}_q^a, \mathbf{w} \in \mathcal{R}_q^m, \mathbf{F}\mathbf{w} = \mathbf{y} \bmod q, \|\mathbf{w}\| \leq B \} \text{ .}$$

This relation is a simplified variant of our relation of interest, which we call the *principal linear relation* (see Section 3 for details). Yet, this simplification allows us to focus on the key aspects of the folding process without over-focusing on the complexities of the full relation, which is tailored as an output for the reduction for R1CS and is, accordingly, more technically nuanced.

Assuming we have  $\mathbf{w}_0$  and  $\mathbf{w}_1$  such that  $(\mathbf{y}_0, \mathbf{w}_0) \in \Xi_{\mathbf{F}}^{\text{lin}}$  and  $(\mathbf{y}_1, \mathbf{w}_1) \in \Xi_{\mathbf{F}}^{\text{lin}}$ , one can define the folding as a (short) linear combination of  $\mathbf{w}_0$  and  $\mathbf{w}_1$ . For simplicity of exposition, we assume that the statement matrices are the same, i.e.  $\mathbf{F}$  is global. Naively folding the two instance witness pairs through a random linear combination leads to a new claim  $(\hat{\mathbf{y}}, \hat{\mathbf{w}}) \in \Xi_{\mathbf{F}}^{\text{lin}}$ , where  $\hat{\mathbf{y}} = \mathbf{y}_0 + c\mathbf{y}_1$  and  $\hat{\mathbf{w}} = \mathbf{w}_0 + c\mathbf{w}_1$ , for  $c \leftarrow \mathcal{D}$  such that  $c$  is short (i.e. its operator norm is bounded by  $\gamma_{\mathcal{D}}$ ). Unfortunately, although  $\hat{\mathbf{w}}$  is a valid witness for the new relation, i.e.,  $\mathbf{F}\hat{\mathbf{w}} = \hat{\mathbf{y}} \bmod q$ , the norm of the witness is not bounded by  $B$  anymore, but rather by  $B\gamma_{\mathcal{D}}$ .

For the security of the folding scheme, one needs to show that the protocol is *extractable*, i.e., one can extract  $\tilde{\mathbf{w}}_0$  and  $\tilde{\mathbf{w}}_1$  such that  $(\mathbf{y}_0, \tilde{\mathbf{w}}_0) \in \Xi_{\mathbf{F}}^{\text{lin}}$  and  $(\mathbf{y}_1, \tilde{\mathbf{w}}_1) \in \Xi_{\mathbf{F}}^{\text{lin}}$ . Unfortunately, such a folding scheme is not extractable in general: one can only extract a witness satisfying a relaxed variant of the relation, i.e.,  $(s_0\mathbf{y}_0, \tilde{\mathbf{w}}_0) \in \Xi_{\mathbf{F}}^{\text{lin}}$  and  $(s_1\mathbf{y}_1, \tilde{\mathbf{w}}_1) \in \Xi_{\mathbf{F}}^{\text{lin}}$  for short  $s_0, s_1 \in \mathcal{R}_q$  (which we call *slack factors*, also known as *short denominators* of the witness).

In more detail, one extracts the witnesses  $\tilde{\mathbf{w}}_0$  and  $\tilde{\mathbf{w}}_1$  in the following way. One runs the prover twice to get  $(\hat{\mathbf{w}}_0, \hat{\mathbf{y}}_0 = \mathbf{y}_0 + c_0\mathbf{y}_1)$  for a short  $c_0 \in \mathcal{R}_q$ , and  $(\hat{\mathbf{w}}_1, \hat{\mathbf{y}}_1 = \mathbf{y}_0 + c_1\mathbf{y}_1)$  for some  $c_1 \in \mathcal{R}_q$ . Wlog, assume that  $c_0 \neq c_1$  (as the challenge space is large). Then,  $\tilde{\mathbf{w}}_1 = (\hat{\mathbf{w}}_0 - \hat{\mathbf{w}}_1)/(c_0 - c_1)$  and  $\tilde{\mathbf{w}}_0 = \hat{\mathbf{w}}_0 - c_0 \cdot \tilde{\mathbf{w}}_1$  so that  $\mathbf{F}\tilde{\mathbf{w}}_0 = \mathbf{y}_0$  and  $\mathbf{F}\tilde{\mathbf{w}}_1 = \mathbf{y}_1$ , yet  $\tilde{\mathbf{w}}_0, \tilde{\mathbf{w}}_1$  are not *short* as they have a short denominator  $c' := c_0 - c_1$ . This denominator is prohibitive for the extraction of the witnesses as it grows exponentially with the number of folding rounds.

To address this issue, LatticeFold [BC25a] and LatticeFold+ [BC25b] invoke two additional protocols: a decomposition and a norm check, which can be pictorially represented as follows (or as some variation of it):

$$\left. \begin{array}{l} (\Xi_{\text{acc}}^{\text{lin}})^\ell \xrightarrow{\text{norm-check}} (\Xi_{\text{acc}}^{\text{lin}'})^\ell \\ \Xi_{\text{input}}^{\text{lin}} \xrightarrow{\text{norm-check}} \Xi_{\text{input}}^{\text{lin}'} \end{array} \right\} \xrightarrow{\text{fold}} \Xi_{\text{folded}}^{\text{lin}} \xrightarrow{\text{decomposition}} (\Xi_{\text{output}}^{\text{lin}})^\ell. \quad (1)$$

In words, one considers an input relation  $\Xi_{\text{input}}^{\text{lin}}$  and an input “accumulated” relation  $\Xi_{\text{acc}}^{\text{lin}}$  (i.e. the relation after several folding steps) and applies the norm check to both relations. This norm

serves as a “checkpoint” for the extraction, which effectively resets the norm to the precise bound of the original relation. Then, one applies the folding step to obtain a new folded relation. To address the growth of the norm in the folding direction (also called the “correctness” direction), as the last step the folded witness gets decomposed into  $\ell$  “digits,” or “chunks,” so that the norm of each digit is the same as that of the original relation. In LatticeFold+,  $\ell = 2$ , so the “accumulated” relation is a pair of relations, the folded relation is a single relation, and the output relation is again a pair of relations. The output serves as an “accumulated” relation for the next round.

The technical difficulties of previous works are the construction of the decomposition and norm-check protocols, which have been addressed using, e.g., so-called “monomial” decomposition in LatticeFold+ [BC25b], or sum-check on many grand-product constraints in LatticeFold [BC25a]. See Section 1.1 for more details on these approaches.

## 2.2 New Framework: Amortized Norm-Refreshing Folding Scheme

In the current paper, we propose a new folding framework, an *amortized norm-refreshing folding scheme*. The main idea is to avoid the norm check and decomposition protocols on the “accumulated” relations, and only apply them on the input relation. Pictorially, we represent the framework as follows:

$$\left. \begin{array}{c} \Xi_{\text{input}}^{\text{lin}} \xrightarrow{\text{decomposition}^*} \Xi_{\text{input}}^{\text{lin}'} \xrightarrow{\text{norm-check}} \Xi_{\text{input}}^{\text{lin}''} \\ \Xi_{\text{acc}}^{\text{lin}} \end{array} \right\} \xrightarrow{\text{fold}} \Xi_{\text{output}}^{\text{lin}},$$

where the decomposition step  $\Xi_{\text{input}}^{\text{lin}} \rightarrow \Xi_{\text{input}}^{\text{lin}'}$  is not always required: importantly, when using our scheme to fold R1CS/CCS constraints over  $\mathbb{F}_q$ , the decomposition step can be skipped (see Remark 1 for a discussion of the implications for recursive verification).

Besides the appealing property of sometimes being able to skip the decomposition step, this framework has an additional benefit: by exploiting the fact that the input accumulated witnesses do not need to be checked at all, we can construct a tailored lightweight decomposition and norm-check procedure, which is not usable in the previous lattice-based folding framework of Eq. (1).

As a downside, since the norm of the input “accumulated” witness is not checked anymore, the norm of the accumulated witness grows with the number of folding rounds. Our key observation is that, despite this, the growth is only by an additive factor (instead of multiplicative) per folding step, as we will explain in Section 2.5. Therefore, upon imposing a bound on the number of folding rounds, the obtained norm growth is acceptable. Notably, for the hardness of the underlying SIS problem, parameters are only mildly affected by the number of folding rounds. Concretely, we impose a bound on the number of folding rounds to be relatively large, e.g.,  $2^{10}$ , which is acceptable in practice.

**Combination with previous frameworks.** The limitation on the number of folding rounds might be unsatisfactory in some applications. We stress that the new folding framework can be naturally combined with the previous lattice-based framework. I.e., we can construct a hybrid folding scheme, where we apply the other frameworks every  $k$  rounds, and our framework in between. That way, we can balance the efficiency and the norm growth. This hybrid scheme is particularly feasible, while considering the connection to the previous framework of LatticeFold+ [BC25b], where the linear relation supported by the folding scheme is almost exactly the relation we consider (subject to notational details). This is similar to bootstrapping in FHE, except that LatticeFold+ is quite efficient.

## 2.3 Building Blocks of Cyclo

The main building blocks of our new amortized norm-refreshing folding scheme Cyclo are the “extension commitment” protocol and the “range check” protocol. We emphasize again that, for the purposes of folding R1CS/CCS instances over a finite field, the extension commitment step can be fully skipped (cf. Remark 1).

**Extension Commitment.** The extension commitment protocol commits to the decomposition  $\mathbf{v} \in \mathcal{R}_q^{m\ell}$  of the witness  $\mathbf{w} \in \mathcal{R}_q^m$  of the input relation with a delayed proof of its correctness; thus, it is a reduction of knowledge. Here,  $B$  is the large bound,  $b$  is the base of the decomposition, and  $\ell := \log_{2b} 2B$ . (Note that  $\mathbf{v}$  has higher dimension than  $\mathbf{w}$ , motivating us to keep  $\ell$  small.) Contrary to the general idea of decomposing witnesses into multiple linear relations (i.e. “horizontally”) [KLNO24, KLNO25a, BC25b, BC25a], we decompose the witness “vertically.” Thus, it remains captured by a single linear relation, which is an important optimization for the communication overhead.

When the witness of the input relation is already of low norm, this step can be skipped altogether. If configured properly, this is the case when using Cyclo to fold R1CS/CCS instances over a finite field (cf. Section 2.6).

The new extension commitment protocol  $\Pi^{\text{ext}}$  is parameterized by public random (but fixed) matrices  $\mathbf{F} \in \mathcal{R}_q^{a \times m}$  and  $\mathbf{R} \in \mathcal{R}_q^{a' \times m\ell}$  (viewed as Ajtai commitments with ranks  $a$  and  $a'$ , respectively), and a challenge space (sampling set)  $\mathcal{C} \subseteq \mathcal{R}_q$ . Wlog, assume  $\ell := \log_{2b} 2B$  and  $\ell_C := \log_2 a$  are integers. We define  $\mathbf{tensor}(\hat{\mathbf{c}}) := (\mathbf{eq}(\hat{\mathbf{c}}; \mathbf{j}))_{j \in \{0,1\}^{\ell_C}} \in \mathcal{R}_q^a$  for the standard indicator (Lagrange) polynomials  $\mathbf{eq}$ .

$\Pi^{\text{ext}}$  works as follows (see Figure 2 for details):

1. The prover holds a witness  $\mathbf{w} \in \mathcal{R}_q^m$  such that  $\mathbf{Fw} = \mathbf{y} \bmod q$  and  $\|\mathbf{w}\| \leq B$ . Here,  $\mathbf{y} \in \mathcal{R}_q^a$ . The prover decomposes  $\mathbf{w}$  into  $\ell$  “digits”  $\mathbf{w}_i \in \mathcal{R}_q^m$  such that  $\mathbf{w} = \sum_{i=0}^{\ell-1} (2b)^i \mathbf{w}_i$  and  $\|\mathbf{w}_i\| < b$  for all  $i$ . Let  $\mathbf{v}^T := (\mathbf{w}_0^T, \dots, \mathbf{w}_{\ell-1}^T)^T \in \mathcal{R}_q^{m\ell}$ .
2. The prover sends a commitment  $\mathbf{t} = \mathbf{Rv} \in \mathcal{R}_q^{a'}$  to  $\mathbf{v}$ .
3. The verifier samples  $\hat{\mathbf{c}} := (\hat{c}_1, \dots, \hat{c}_{\ell_C-1}) \leftarrow \mathcal{C}^{\ell_C}$  and defines  $\mathbf{c} := \mathbf{tensor}(\hat{\mathbf{c}})$ .
4. The prover and the verifier define an additional constraint to ensure that  $\mathbf{f}^T \mathbf{v} = \langle \mathbf{c}, \mathbf{y} \rangle \bmod q$ , where  $\mathbf{f}^T := \mathbf{c}^T ((2b)^0, (2b)^1, \dots, (2b)^{\ell-1}) \otimes \mathbf{F})^5$ . Indeed,  $((2b)^0, (2b)^1, \dots, (2b)^{\ell-1}) \otimes \mathbf{F}) \mathbf{v} = ((2b)^0 \mathbf{F}, \dots, (2b)^{\ell-1} \mathbf{F}) \mathbf{v} = \mathbf{F}(\sum_{i=0}^{\ell-1} (2b)^i \mathbf{w}_i) = \mathbf{Fw} = \mathbf{y}$  and thus  $\mathbf{f}^T \mathbf{v} = \langle \mathbf{c}, \mathbf{y} \rangle$ .

The constraint guarantees that the committed  $\mathbf{v}$  is indeed a valid decomposition of a witness of the input relation. The new constraint is appended to the input constraint so that

$$\begin{pmatrix} \mathbf{R} \\ \mathbf{f}^T \end{pmatrix} \mathbf{v} = \begin{pmatrix} \mathbf{t} \\ \langle \mathbf{c}, \mathbf{y} \rangle \end{pmatrix} \bmod q$$

serves as a new constraint with a new witness  $\mathbf{v}$ .

We designed  $\Pi^{\text{ext}}$  to reduce the norm of the witness in the folding direction, making the range check (that has a linear complexity in  $b$ ) more efficient.  $\Pi^{\text{ext}}$  is the most expensive part of Cyclo, requiring  $a'm\ell = a'm \log_{2b} 2B$  ring element multiplications. Importantly, the choice of  $b$  provides a trade-off between the efficiencies of the extension commitment and the range check.

**Range Check.** The range check is a reduction of knowledge to prove that the witness  $\mathbf{w} \in \mathcal{R}_q^m$  of the input relation is indeed small, i.e.,  $\|\mathbf{w}\| \leq B$  for some  $B$ . It reduces it to a linear constraint that

<sup>5</sup> Note that the decomposition is done in the base  $2b$  as opposed to  $b$  as we take advantage of the sign.

is appended to the list of input constraints. Our range check  $\Pi^{\text{range}}$  is the same as LatticeFold's. However, LatticeFold applies it to many witness chunks, while we apply it to only one witness vector. Let  $\ell := \lceil \log_2(\varphi m) \rceil$ . Let  $\text{MLE}[\mathbf{z}]$  be the multilinear extension of  $\mathbf{z} \in \mathbb{F}_q^{m\varphi}$  over a Boolean hypercube, i.e., the vector of evaluations of  $\text{MLE}[\mathbf{z}]$  on  $\{0, 1\}^\ell$  is equal to  $\mathbf{z}$ . Let  $f(\mathbf{X}) = \text{MLE}[\text{cf}(\mathbf{w})]$ , with  $f(\mathbf{x}) = \text{cf}(\mathbf{w})_{\mathbf{x}}$  for  $\mathbf{x} \in \{0, 1\}^\ell$ . We use the standard observation that  $\|\mathbf{w}\| \leq B$  iff  $g(\mathbf{X}) := \prod_{i=-B}^B (f(\mathbf{X}) - i)$  vanishes on the hypercube, which holds iff  $\text{MLE}[(g(\mathbf{j}))_{\mathbf{j} \in \{0, 1\}^\ell}] = \sum_{\mathbf{j} \in \{0, 1\}^\ell} g(\mathbf{j}) \text{eq}(\mathbf{j}, \mathbf{X})$  is a zero polynomial. The verifier uses Schwartz-Zippel and sum-check to test the latter.

More precisely,  $\Pi^{\text{range}}$  works as follows (see Figure 1 for details):

1. The verifier samples a random  $\boldsymbol{\eta}$ .
2. Let  $\hat{f}(\mathbf{X}) = \prod_{i=-B}^B (f(\mathbf{X}) - i) \cdot \text{eq}(\mathbf{X}, \boldsymbol{\eta})$ . The prover and the verifier use the sum-check to reduce the statement that  $\sum_{\mathbf{x} \in \{0, 1\}^\ell} \hat{f}(\mathbf{x}) = 0$  to the statement that  $\hat{f}(\mathbf{u}) = s$  for a random challenge  $\mathbf{u} \in \mathbb{Z}_q^\ell$ .
3. The prover sends  $t = f(\mathbf{u})$  to the verifier, who checks  $\prod_{i=-B}^B (t - i) \cdot \text{eq}(\mathbf{u}, \boldsymbol{\eta}) = s$  (assuming  $t$  is correctly computed).
4. The prover delays the proof that  $t = f(\mathbf{u})$  by appending an additional row to the relation to show that  $\langle \text{tensor}(\mathbf{u}), \text{cf}(\mathbf{w}) \rangle = \text{MLE}[\mathbf{w}](\mathbf{u}) = t$ . In the ring setting, this translates to  $\langle \text{cf}_V^{-1}(\mathbf{u}), \mathbf{w} \rangle = \tilde{t}$  for a  $\tilde{t} \in \mathcal{R}_q$  such that  $\text{ct}(\tilde{t}) = t$ .

This induces a standard sum-check soundness error. To reduce the soundness error, we execute  $\Pi^{\text{range}}$  over an extension field  $\mathbb{F}_{q^\epsilon}$ .

## 2.4 Cyclo: Putting the Building Blocks Together

Next, we combine the building blocks to construct the new folding scheme Cyclo. For simplicity, we assume that we fold only one relation with the accumulator. The steps of Cyclo are as follows (see Figure 3 for details):

1. The prover and the verifier execute the extension commitment to commit to the decomposition  $\mathbf{v} \in \mathcal{R}_q^{m\ell}$  of the witness  $\mathbf{w} \in \mathcal{R}_q^m$  of the input relation.
2. The prover and the verifier execute the range check to prove that the witness  $\mathbf{w}$  of the input relation is small.
3. The prover and the verifier unify the statement of the new relation and the accumulator by expressing them as a sum-check claim and executing sum-check on shared randomness. In this step, a sum-check is used to ensure that the two instances being folded include the same points  $(\mathbf{r}_i)_{i \in [k]}$  (see the definition of the principal linear relation in Section 3). Similar steps are taken in LatticeFold, LatticeFold+, and Neo.
4. The prover and the verifier perform a random linear combination of the input relation and the “accumulated” relation using a short challenge  $c \in \mathcal{R}_q$  to obtain a new folded relation.

This intuition naturally generalizes to the case of  $L$  “input” relations, i.e., the input relation is then folded with multiple challenges  $\mathbf{c} \in \mathcal{R}_q^L$ .

## 2.5 Norm growth: completeness and soundness

We next discuss the norm growth of the witnesses in our overall scheme described above. In the correctness direction, i.e., the folding direction, the norm of the witness grows by an additive factor of  $L\gamma b$ , since the challenge is only multiplied with the “extended witness” of the input relation,

which has norm bounded by  $b$  due to the extension commitment. Here,  $L$  is the number of folded input relations and  $\gamma$  corresponds to the operator norm of the challenge. This approach is crucially different from the previous frameworks, where the norm grows multiplicatively in the correctness direction<sup>6</sup>.

In the extraction direction, the norm of the witness grows by an additive factor of  $Lb$  in the accumulated relation and the norm of the witness of the input relation is precisely maintained. The reason for that is that the extraction for the input relation is guaranteed by the range check protocol, which ensures that the witness of the input relation is *exactly* bounded by  $b$ . The extraction for the “accumulated” relation is more delicate as the relation is not norm-checked explicitly. However, since the output witness  $\hat{\mathbf{v}}$  is a linear combination of the input “extended witness”  $\mathbf{v}_i$  and the “accumulated” witness  $\mathbf{v}$ ,  $\hat{\mathbf{v}} = \mathbf{v} + \sum_{i \in [L]} c_i \mathbf{v}_i$ , we can extract the witness of the relation as  $\tilde{\mathbf{v}} = \hat{\mathbf{v}} - \sum_{i \in [L]} c_i \tilde{\mathbf{v}}_i$  for the extracted extended witnesses  $\tilde{\mathbf{v}}_i$  of the input relation. Since  $\|\tilde{\mathbf{v}}_i\| \leq b$  and  $c_i$  are short, we have that  $\|\tilde{\mathbf{v}}\| \leq \|\hat{\mathbf{v}}\| + L\gamma b$ , effectively contributing to an additive norm growth in the extraction direction.

**From Folding to IVC and PCD** The folding scheme can be used (generically) to construct an IVC [Val08,NPR19]. The construction of PCD [CT10,BCL<sup>+</sup>21,CCG<sup>+</sup>23] is less straightforward, since the accumulator relation in our construction is of a different type (with different parameters) than the input relation. Furthermore, the accumulator in our construction serves a “special role,” as it is not norm-checked and we enforce that, during the folding step, the accumulated witness is not multiplied by the challenge. We do not resolve these issues directly, but we emphasize that in practical settings, we envision Cyclo being used for proving sequential computation branches and then offloading the merging of accumulators to a separate protocol, such as LatticeFold+ [BC25b]. In this sense, LatticeFold+ (or a similar protocol) would serve a dual role of merging the accumulators and refreshing the norm, while Cyclo would serve the role of folding the input relations with the accumulator.

## 2.6 From R1CS over $\mathbb{F}_q$ to the Principal Linear Relation

Our second family of technical contributions provides a reduction from R1CS (or CCS) constraints over  $\mathbb{F}_q$  to our principal linear relation over  $\mathcal{R}_q$ . Most of the approach is ultimately equivalent to Neo’s [NS25], but, as we mentioned, our formulation is substantially different and uses only cyclotomic rings and fields, and additive homomorphisms. As such, we believe it can help incorporate the same or similar ideas in other protocols in a more streamlined manner.

We begin with an R1CS relation over  $\mathbb{F}_q$ , namely,

$$\Xi_{(\mathbf{M}_i)_{i \in [3]}}^{\text{R1CS}} := \left\{ \begin{array}{l} \mathbf{x}, \mathbf{w} : \\ \mathbf{x} \in \mathbb{F}_q^\ell, \mathbf{w} \in \mathbb{F}_q^{m-\ell-1}, \mathbf{z} = (\mathbf{x}, 1, \mathbf{w}) \in \mathbb{F}_q^m, \\ (\mathbf{M}_0 \cdot \mathbf{z}) \circ (\mathbf{M}_1 \cdot \mathbf{z}) = \mathbf{M}_2 \cdot \mathbf{z} \end{array} \right\}.$$

where  $m, \ell$  are size parameters, and  $\mathbf{M}_i \in \mathbb{F}_q^{m \times m}, i \in [3]$  are public fixed matrices.

Our goal is to build a reduction of knowledge from  $\Xi^{\text{R1CS}}$  to our principal linear relation. First of all, as is customary with reductions of knowledge, we seek to introduce commitments to the witness

<sup>6</sup> We remark that this approach is not possible in the previous frameworks. In LatticeFold+, the accumulated relation is represented as a pair of linear relations and therefore the folding step has to combine those columns together, effectively contributing to the multiplicative norm growth. A similar remark shall be drawn about the extractability.

in our relation. In particular, we seek to commit to  $\mathbf{w}$  (or  $\mathbf{z} = (\mathbf{x}, 1, \mathbf{w})$ ) using Ajtai's commitment. However, this cannot be done naively, since  $\mathbf{z}$  has in principle arbitrary norm, and hence a naive commitment of the form  $\mathbf{Az}$  would not be binding.

We choose to commit to  $\mathbf{z}$  in a similar manner to Neo [NS25], though our description of the commitment is slightly different in language. Before explaining how the commitment works, we introduce some concepts. Let  $k$  be a positive integer, and define the following map:

$$\theta_k : \mathcal{R}_q \rightarrow \mathbb{F}_q \text{ by } f(X) \mapsto f(k) \pmod{q}.$$

One can check that  $\theta_k$  is an  $\mathbb{F}_q$ -module morphism, when looking at  $\mathcal{R}_q$  as the  $\mathbb{F}_q$ -module consisting of all polynomials of degree less than  $\deg(\Phi_f(X))^7$ . Note that  $\mathcal{R}_q$  is in fact an  $\mathbb{F}_q$ -vector space. We opt to use the terminology of modules in our presentation, in view of possible future generalizations of our framework.

Let  $\ell_k(q) = \lfloor \log_k q \rfloor$ , and assume  $\ell_k(q) < \varphi$ . Given a base- $b$  extension  $c = \sum_{i=0}^{\ell_k(q)-1} c_i k^i \in \mathbb{F}_q$  with  $c_i \in [0, k-1]$ , we define the element  $p_c(X) \in \mathcal{R}_q$  as  $p_c(X) = \sum_{i=0}^{\ell_k(q)-1} c_i X^i$ . Then  $\theta_k(p_c(X)) = c$ . Given  $c \in \mathbb{F}_q$ , let  $\theta_k^{-1}(c)$  be the unique polynomial  $p_c(X)$ . We extend  $\theta_k$  and  $\theta_k^{-1}$  naturally to vectors. Note that if  $B$  satisfies  $B > k$ , then the norm of  $p_c(X)$  is smaller than  $B$  for all  $c \in \mathbb{F}_q$ . We commit to  $\mathbf{z} \in \mathbb{F}_q^m$  by committing to the vector of ring elements  $\theta_k^{-1}(\mathbf{z}) \in \mathcal{R}_q^m$ , so that our commitment is  $\mathbf{Az}'$  for a vector  $\mathbf{z}' \in \mathcal{R}_q^m$ , with  $\|\mathbf{z}'\| < B$  and  $\theta_k(\mathbf{z}') = \mathbf{z}$ .

One can see that this commitment approach is precisely the same as the one in Neo [NS25]. As such, the cost of computing  $\mathbf{Az}'$  is also linear in the number of nonzero digits of the base- $k$  representation of the elements in  $\mathbf{z}$ .

We next define the following committed version of the R1CS relation, where the vector  $\mathbf{z}$  is lifted from  $\mathbb{F}_q$  through  $\theta_k^{-1}$  onto  $\mathcal{R}_q$ , and committed with the Ajtai commitment as  $\mathbf{y} = \mathbf{Az}$ . Importantly, the actual R1CS constraint is not lifted to  $\mathcal{R}_q$ . Because the relation involves two different algebraic structures,  $\mathcal{R}_q$  and  $\mathbb{F}_q$ , we call it *committed hybrid R1CS relation*:

$$\Xi^{\text{com-hyb-R1CS}} := \left\{ \begin{array}{l} (\mathbf{x}, \mathbf{y}), \mathbf{w} : \\ \mathbf{x} \in \mathcal{R}_q^\ell, \mathbf{y} \in \mathcal{R}_q^a, \mathbf{w} \in \mathcal{R}_q^{m-\ell-1}, \mathbf{z} = (\mathbf{x}, 1, \mathbf{w}) \in \mathcal{R}_q^m, \\ (\mathbf{M}_0 \cdot \theta_k(\mathbf{z})) \circ (\mathbf{M}_1 \cdot \theta_k(\mathbf{z})) - \mathbf{M}_2 \cdot \theta_k(\mathbf{z}) = 0, \\ \mathbf{Az} = \mathbf{y}, \|\mathbf{z}\| \leq B \end{array} \right\}.$$

We highlight in blue the differences with the original R1CS relation. Now, if one is given an instance  $(\mathbf{x}, \mathbf{y}) \in \mathcal{R}_q^{\ell+a}$  of  $\Xi^{\text{com-hyb-R1CS}}$  and is able to extract a valid witness  $\mathbf{w} \in \mathcal{R}_q^{m-\ell-1}$  for it, then  $\theta_k(\mathbf{w}) \in \mathbb{F}_q^{m-\ell-1}$  is a valid witness for the instance  $\theta_k(\mathbf{x}) \in \mathbb{F}_q^\ell$  of  $\Xi^{\text{R1CS}}$ . Conversely, if one is given an instance  $\mathbf{x} \in \mathbb{F}_q^\ell$  of  $\Xi^{\text{R1CS}}$ , and extracts a valid witness  $\mathbf{w} \in \mathbb{F}_q^{m-\ell-1}$  for it, then  $\theta_k^{-1}(\mathbf{w}) \in \mathcal{R}_q^{m-\ell-1}$  is a valid witness for the instance  $(\theta_k^{-1}(\mathbf{x}), \mathbf{y}) \in \mathcal{R}_q^{\ell+a}$  of  $\Xi^{\text{com-hyb-R1CS}}$ , where  $\mathbf{y} = \mathbf{Az}$  and  $\mathbf{z} = (\theta_k^{-1}(\mathbf{x}), 1, \theta_k^{-1}(\mathbf{w})) \in \mathcal{R}_q^m$ . Hence, from here on we can focus on constructing a reduction of knowledge for  $\Xi^{\text{com-hyb-R1CS}}$ .

Next, we construct our reduction of knowledge from  $\Xi^{\text{com-hyb-R1CS}}$  to the principal linear relation by following the blueprint from Hypernova's linearization step [KS24]. Namely, given  $(\mathbf{x}, \mathbf{y})$  and  $\mathbf{w}$ , let  $\mathbf{w}' = (\mathbf{x}, 1, \mathbf{w})$ . Let  $Q(\mathbf{Y}) = Q_0(\mathbf{Y})Q_1(\mathbf{Y}) - Q_2(\mathbf{Y})$  and  $Q_i(\mathbf{Y})$  be the multilinear polynomials on  $\log m$  variables  $\mathbf{Y}$ :

$$Q_i(\mathbf{Y}) = \sum_{\mathbf{b}' \in \{0,1\}^{\log m}} \text{MLE}[\mathbf{M}_i](\mathbf{Y}, \mathbf{b}') \text{MLE}[\theta_k(\mathbf{w}')](\mathbf{b}').$$

<sup>7</sup> We note that  $\theta_k$  is not, in general, a ring homomorphism. It is such if and only if  $\Phi_f(k) = 0 \pmod{q}$ , though this is not needed in this work.

Now, the prover and the verifier run the sum-check protocol *over an extension field*<sup>8</sup>  $\mathbb{F}_{q^e}$  (crucially, not over  $\mathcal{R}_{q^e}$ ) to reduce the claim  $\sum_{\mathbf{b} \in \{0,1\}^{\log m}} Q(\mathbf{u})\text{eq}(\mathbf{b}; r) = 0$  to the claim  $Q(\mathbf{u})\text{eq}(\mathbf{u}; r) = c$  for a random point  $\mathbf{u} \in \mathbb{F}_{q^e}^{\log m}$  and certain field element  $c \in \mathbb{F}_{q^e}$ . Now, as is usual in this type of reduction, the prover *could* publish the values  $Q_i(\mathbf{u})$  (but in our scheme it won't), which we denote  $d_i$ , for  $i \in [3]$ , and verifier asserts that  $(d_0 d_1 - d_2)\text{eq}(\mathbf{u}, r) = c$ . This way, we have so far reduced the claim that  $((\mathbf{x}, \mathbf{y}), \mathbf{w}) \in \Xi^{\text{com-hyb-R1CS}}$  to the claim that  $((\mathbf{x}, \mathbf{y}), \mathbf{w})$  satisfies

$$\sum_{\mathbf{b}' \in \{0,1\}^{\log m}} \text{MLE}[\mathbf{M}_i](\mathbf{u}, \mathbf{b}') \text{MLE}[\theta_k(\mathbf{w}')](\mathbf{b}') = d_i . \quad (2)$$

Here, recall  $\mathbf{w}' = (\mathbf{x}, 1, \mathbf{w})$ . The claim also includes the statement

$$\mathbf{A}\mathbf{w}' = \mathbf{y}, \quad \text{cf}(\mathbf{w}') \subseteq [0, B)^{m\varphi} . \quad (3)$$

We are now ready to reduce the above claim into a claim about the principal linear relation. The main observation is that, because  $\theta_k$  is a  $\mathbb{F}_q$ -module homomorphism, we have, for all  $\mathbf{b}' \in \{0,1\}^{\log m}$ :  $\text{MLE}[\theta_k(\mathbf{w}')](\mathbf{b}') = \theta_k(\text{MLE}[\mathbf{w}'](\mathbf{b}'))$ , and so (2) is true if and only if

$$\sum_{\mathbf{b}' \in \{0,1\}^{\log m}} \text{MLE}[\mathbf{M}_i](\mathbf{u}, \mathbf{b}') \text{MLE}[\mathbf{w}'](\mathbf{b}') = d'_i \quad (4)$$

for some  $d'_i \in \mathcal{R}_{q^e}$  such that  $\theta_k(d'_i) = d_i$ , where  $i \in [3]$ .

Thus, instead of having the prover publish the values  $d_i$ , it publishes  $d'_i$ , for  $i \in [3]$ . Our initial claim is then reduced to the claim that  $((\mathbf{x}, \mathbf{y}), \mathbf{w})$  satisfies (4) and (3). Note that, now, all constraints occur over  $\mathcal{R}_q$ . This claim is essentially a claim about  $(\mathbf{y}, \mathbf{w}' = (\mathbf{x}, 1, \mathbf{w}))$  belonging to the principal linear relation (for a suitable choice of parameters). The only aspect left to deal with is the presence of the public prefix  $(\mathbf{x}, 1)$  in the witness  $\mathbf{w}'$ . This does not fit the definition of our principal linear relation  $\Xi^{\text{lin}}$  because such a relation does not expose a public prefix of the witness vector. While we could have defined  $\Xi^{\text{lin}}$  to accommodate such a prefix, we choose instead to add one more step in our reduction from  $\Xi^{\text{com-hyb-R1CS}}$  to  $\Xi^{\text{lin}}$ . Namely, we have the verifier sample a random point  $\mathbf{v} \in \mathcal{R}_{q^e}^{\log(\ell+1)}$  and compute  $e = \text{MLE}[(\mathbf{x}, 1)](\mathbf{v})$ , and we add the evaluation claim  $\text{MLE}[\mathbf{w}'](\mathbf{v}, \mathbf{0}) = e$  to our reduced claim. One can see that if an extractor outputs  $\mathbf{w}'$  satisfying  $\text{MLE}[\mathbf{w}'](\mathbf{v}, \mathbf{0}) = e$ , then  $\mathbf{w}'$  starts with  $(\mathbf{x}, 1)$  except with negligible probability. This allows us to drop the public prefix  $(\mathbf{x}, 1)$  in our reduced claim.

The final reduced claim consists of Eqs. (3) and (4) and  $\text{MLE}[\mathbf{w}'](\mathbf{v}, \mathbf{0}) = e$ .

*Skipping the extension commitment step* If  $k$  is sufficiently small, i.e. if  $k \leq b$  following the notation used in the extension commitment step, then the output witness of the above reduction of knowledge has norm at most  $b$ . In this scenario, there is no need to follow up with the extension commitment step: prover and verifier can simply proceed to the range test step.

## 2.7 Concrete Efficiency of the Folding Scheme

In Section 6.1, we provide a practical overview of our evaluation methodology for the amortized norm-refreshing folding scheme. Our focus is on measuring the computational efficiency of the protocol, specifically benchmarking the most resource-intensive operations. In particular, we compare the commitment computations—namely, the “double commitment” used in LatticeFold+ [BC25b]

<sup>8</sup> As we mentioned, running a sum-check over  $\mathbb{F}_{q^e}$  is significantly cheaper than doing so over  $\mathcal{R}_{q^e}$ , in terms of prover and verifier times.

and our “extension commitment” protocol. By isolating these components, we assess the concrete performance improvements achieved by our scheme. The evaluation demonstrates that our protocol reduces the computational cost of commitment generation, which is the dominant factor in the overall runtime. This benchmarking highlights the practical advantages of our folding scheme in terms of efficiency, without necessitating a full implementation of the entire protocol. Furthermore, we believe that our toolset for measuring the efficiency of the individual components will be useful for future work in this area.

We also remark again that, when applying Cyclo on R1CS/CCS instances over a finite field, the extension commitment step can be skipped altogether.

# 3 Preliminaries

Let  $\mathbb{N} = \{1, 2, \dots\}$  denote natural numbers and  $\lambda \in \mathbb{N}$  be the security parameter. For  $n \in \mathbb{N}$ , we write  $[n] := \{0, \dots, n-1\}$  counting from 0. For multidimensional ranges, we use the shorthand  $(i, j, k) \in [n, m, \ell]$  for  $i \in [n]$ ,  $j \in [m]$ , and  $k \in [\ell]$ . The logarithm  $\log$  is base-2. To represent  $\mathbb{Z}_q$  we use the balanced representation, i.e.  $\{-\lceil q/2 \rceil + 1, \dots, \lfloor q/2 \rfloor\}$ . We use bold lower-case letters to denote vectors  $\mathbf{v}$  and bold upper-case letters to denote matrices  $\mathbf{M}$ . For vectors, we use subscript with a specified range to denote the subvector, e.g.  $\mathbf{v}[1, |\mathbf{v}|]$  denotes the vector without the element at the 0-th index. We denote with  $\mathbf{1}_n$  the column vector consisting of ones of length  $n$ . For matrices (or vectors)  $\mathbf{M}_0, \dots, \mathbf{M}_{k-1}$  of appropriate dimensions, we write  $(\mathbf{M}_i)_{i \in [k]}$  for horizontal concatenation. We assume that the base of the logarithm is 2 unless specified otherwise.

**Cyclotomic Fields.** Let  $\mathcal{R} := \mathbb{Z}[X]/\langle \Phi_{\mathfrak{f}} \rangle$  be the cyclotomic ring defined by the  $\mathfrak{f}$ -th cyclotomic polynomial  $\Phi_{\mathfrak{f}}$  for a conductor  $\mathfrak{f} \in \mathbb{N}$  with  $\mathfrak{f} \not\equiv 2 \pmod{4}$  and degree  $\varphi = \varphi(\mathfrak{f})$  (where  $\varphi$  is Euler’s totient function). We endow  $\mathcal{R}$  with a geometry via the coefficient embedding  $\mathbf{cf}_{\mathbf{b}} : \mathcal{R} \rightarrow \mathbb{Z}^{\varphi}$  (for a given basis  $\mathbf{b}$ ). Specifically, for a given  $\mathbb{Z}$ -basis  $\mathbf{b} = (b_i)_{i \in [\varphi]}$  of  $\mathcal{R}$  and an element  $x = \sum_{i \in [\varphi]} x_i b_i \in \mathcal{R}$ , we write  $\mathbf{cf}_{\mathbf{b}}(x) = \mathbf{cf}_{\mathbf{b}}(\sum_{i \in [\varphi]} x_i b_i) := (x_i)_{i \in [\varphi]}$ .

The *powerful basis* of  $\mathcal{R}$  is  $\mathbf{b} = (1, X, \dots, X^{\varphi-1})$  for prime-power conductor  $\mathfrak{f}$ . The basis generalizes to the composite conductor  $\mathfrak{f} = \prod_{i \in [k]} \mathfrak{f}_i^{e_i}$  for prime  $\mathfrak{f}_i$  via tensor product,  $\mathbf{b} = \bigotimes_{i \in [k]} (1, X_{\mathfrak{f}_i}, \dots, X_{\mathfrak{f}_i}^{\varphi(\mathfrak{f}_i)-1})$ . If  $\mathbf{b}$  is the standard powerful basis, we omit  $\mathbf{b}$  from the subscript of  $\mathbf{cf}_{\mathbf{b}}$ . Thus,

$$\mathbf{cf}(\sum_{i \in [\varphi]} x_i X^i) = \mathbf{x} \text{ and } \mathbf{cf}^{-1}(\mathbf{x}) = \sum_{i \in [\varphi]} x_i X^i \text{ for } \mathbf{x} \in \mathbb{Z}^{\varphi}. \quad (5)$$

We extend the notation of  $\mathbf{cf}_{\mathbf{b}}$  naturally to vectors, i.e., if  $\mathbf{x} = (x_i)_{i \in [m]} \in \mathcal{R}^m$ , then  $\mathbf{cf}_{\mathbf{b}}(\mathbf{x}) := (\mathbf{cf}_{\mathbf{b}}(x_i))_{i \in [m]}^T$  are defined as concatenations. For a prime modulus  $q \in \mathbb{N}$ , we write  $\mathcal{R}_q := \mathcal{R}/q\mathcal{R}$ . We denote by  $\mathcal{R}^{\times}$  and  $\mathcal{R}_q^{\times}$  the sets of units in  $\mathcal{R}$  and  $\mathcal{R}_q$  respectively.

Further, we define  $\mathcal{R}_{q^e} := \mathbb{F}_{q^e}[X]/\langle \Phi_{\mathfrak{f}} \rangle$ , i.e., the quotient ring defined by the polynomial ring  $\mathbb{F}_{q^e}[X]$  and the ideal generated by  $\Phi_{\mathfrak{f}}$  (with the coefficients implicitly lifted to  $\mathbb{F}_{q^e}$ ). If  $\mathcal{R}_q \cong (\mathbb{F}_{q^e})^{\varphi/e}$ , then  $\mathcal{R}_{q^e} \cong (\mathbb{F}_{q^e})^{\varphi}$  as shown in Lemma 1. We will use the ring  $\mathcal{R}_{q^e}$  in some protocols where the witness has coefficients in  $\mathbb{Z}_q$  but the operations are performed over the extension field  $\mathbb{F}_{q^e}$  to amplify the soundness.

**Lemma 1.** *Let  $q$  be a prime,  $\mathfrak{f} \in \mathbb{N}$  be a conductor with  $\varphi = \varphi(\mathfrak{f})$ , and  $e \in \mathbb{N}$  be the multiplicative order of  $q$  modulo  $\mathfrak{f}$  (which implies that  $\mathcal{R}_q \cong (\mathbb{F}_{q^e})^{\varphi/e}$ ). Then, the ring  $\mathcal{R}_{q^e} := \mathbb{F}_{q^e}[X]/\langle \Phi_{\mathfrak{f}} \rangle$  is isomorphic to  $(\mathbb{F}_{q^e})^{\varphi}$ .*

*Proof.* Since  $q$  has multiplicative order  $e$  modulo  $\mathfrak{f}$ , we have  $q^e \equiv 1 \pmod{\mathfrak{f}}$ . This means that  $\mathbb{F}_{q^e}$  contains a primitive  $\mathfrak{f}$ -th root of unity. Therefore, all  $\varphi$  primitive  $\mathfrak{f}$ -th roots of unity lie in  $\mathbb{F}_{q^e}$ , which

implies that the cyclotomic polynomial  $\Phi_f$  splits completely into linear factors over  $\mathbb{F}_{q^e}$  as all of its roots are in  $\mathbb{F}_{q^e}$ . By the Chinese Remainder Theorem, we have the isomorphism  $\mathbb{F}_{q^e}[X]/\langle\Phi_f\rangle \cong \prod_{j \in [\varphi]} \mathbb{F}_{q^e}[X]/\langle X - \alpha_j \rangle$  where  $\alpha_j$  are the roots of  $\Phi_f$  in  $\mathbb{F}_{q^e}$ . Each factor  $\mathbb{F}_{q^e}[X]/\langle X - \alpha_j \rangle$  is isomorphic to  $\mathbb{F}_{q^e}$ , yielding the desired isomorphism.

**Trace Map.** For any Galois extension  $\mathcal{M}/\mathcal{L}$ , the field trace can be computed as  $\text{Trace}_{\mathcal{M}/\mathcal{L}} : \mathcal{M} \rightarrow \mathcal{L}$ ,  $\text{Trace}_{\mathcal{M}/\mathcal{L}}(x) := \sum_{\sigma_j \in \text{Gal}(\mathcal{M}/\mathcal{L})} \sigma_j(x)$ . If  $x \in \mathcal{O}_{\mathcal{M}}$ , then  $\text{Trace}_{\mathcal{M}/\mathcal{L}}(x) \in \mathcal{O}_{\mathcal{L}}$ . We may therefore abuse notation and write  $\text{Trace}_{\mathcal{O}_{\mathcal{L}}/\mathcal{O}_{\mathcal{M}}}(x) := \text{Trace}_{\mathcal{M}/\mathcal{L}}(x)$ . Furthermore, for any  $q \in \mathbb{N}$ , if  $x = x' \bmod q\mathcal{O}_{\mathcal{M}}$ , we have  $\text{Trace}_{\mathcal{O}_{\mathcal{L}}/\mathcal{O}_{\mathcal{M}}}(x) = \text{Trace}_{\mathcal{O}_{\mathcal{L}}/\mathcal{O}_{\mathcal{M}}}(x') \bmod q$  due to linearity. We can therefore write  $\text{Trace}_{\mathcal{O}_{\mathcal{L}}/\mathcal{O}_{\mathcal{M}}}(y)$  for  $y \in \mathcal{O}_{\mathcal{M}}/q\mathcal{O}_{\mathcal{M}}$  without ambiguity. When  $\mathcal{L} = \mathbb{Q}$ , we drop the subscript and write  $\text{Trace} = \text{Trace}_{\mathcal{O}_{\mathcal{M}}/\mathbb{Z}} = \text{Trace}_{\mathcal{M}/\mathbb{Q}}$ .

**Lemma 2 (Lemma 1 from [KLNO25b]).** *Let  $q$  be an unramified prime, i.e.  $q \nmid f$ , and  $\mathcal{R}$  be the ring of integers of a cyclotomic field  $\mathcal{K}$ . For any  $\mathbb{Z}$ -basis  $\mathbf{b} = (b_i)_{i \in [\varphi]} \in \mathcal{R}^\varphi$  of  $\mathcal{R}$ , there exists a basis  $\mathbf{b}^\vee = (b_i^\vee)_{i \in [\varphi]} \in \mathcal{R}^\varphi$  such that  $\text{Trace}(b_i \cdot b_j^\vee) = \delta_{i,j} \bmod q$ , where  $\delta_{i,j}$  denotes the Kronecker delta, for all  $i, j \in [\varphi]$ .*

In general,  $b_j^\vee = f^\dagger \cdot \frac{f}{\Phi_f'(X)} X^{\varphi-j-1} \pmod{q\mathcal{R}}$ , where  $f^\dagger$  satisfies  $f \cdot f^\dagger \equiv 1 \pmod{q}$ . If  $f = 2^k$  then  $b_0^\vee = \varphi^{-1} = (2^{k-1})^{-1} \pmod{q\mathcal{R}}$  and  $b_j^\vee = \varphi^{-1} X^{\varphi-j} = (2^{k-1})^{-1} X^{\varphi-j} \pmod{q\mathcal{R}}$  for  $j > 0$ . While considering the coefficient embedding with respect to the basis  $\mathbf{b}^\vee$ , where  $\mathbf{b}$  is a powerful basis, we write  $\text{cf}_\vee = \text{cf}_{\mathbf{b}^\vee}$ . Thus,  $\text{cf}_\vee^{-1}(\mathbf{x}) = \sum x_i b_i^\vee$ .

**Multilinear extensions.** Let  $\ell = \log(m\varphi)$ . For  $\mathbf{x}, \mathbf{u} \in \mathbb{Z}_q^\ell$ , define the indicator (Lagrange) polynomial  $\text{eq}(\mathbf{x}, \mathbf{t}) := \prod_{i=1}^\ell (x_i t_i + (x_i - 1)(t_i - 1)) \in \mathbb{Z}_q[X_1, \dots, X_\ell]$ . Clearly,  $\text{eq}(\mathbf{x}, \mathbf{t}) = 1$  iff  $\mathbf{x} = \mathbf{t} \in \{0, 1\}^\ell$  and 0 on all other Boolean points. For  $\mathbf{t} = (t_0, \dots, t_{\ell-1}) \in \mathbb{Z}_q^\ell$ , let  $\text{tensor}(\mathbf{t}) := (\text{eq}(\mathbf{j}, \mathbf{t}))_{\mathbf{j} \in \{0, 1\}^\ell} \in \mathbb{Z}_q^{2^\ell} \in \mathbb{Z}_q^{m\varphi}$  be the vector with entries  $\text{eq}(\mathbf{j}, \mathbf{t})$  indexed by  $\mathbf{j} \in \{0, 1\}^\ell$  in a lexicographic order. For  $\mathbf{u} \in \mathbb{Z}_q^{2^\ell}$ , the multilinear extension  $\text{MLE}[\mathbf{u}] \in \mathbb{Z}_q[X_0, \dots, X_{\ell-1}]$  is a multilinear polynomial interpolating  $\mathbf{u}$ : It is the multilinear polynomial with  $\text{MLE}[\mathbf{u}](\mathbf{e}_j) = u_j$  for all Boolean basis points  $\mathbf{e}_j \in \{0, 1\}^\ell$  in a lexicographic order. Equivalently, for  $f = \text{MLE}[\mathbf{u}]$ ,  $\langle \text{tensor}(\mathbf{t}), \mathbf{u} \rangle = \sum_{\mathbf{j} \in \{0, 1\}^\ell} u_j \text{eq}(\mathbf{j}, \mathbf{t}) = f(\mathbf{t})$ .

**Operator norm and expansion factor.** Fix the *coefficient* embedding  $\text{cf}$  above. For  $c \in \mathcal{R}_q$ , let  $\|c\|_{\text{op}} := \sup_{t \in \mathcal{R}_q \setminus \{0\}} \frac{\|t \cdot c\|_\infty}{\|t\|_\infty}$ , where  $\|\cdot\|_\infty$  is the coefficient  $\ell_\infty$ -norm under this embedding. For a challenge set  $S \subseteq \mathcal{R}_q$ , set  $\gamma_S := \max_{c \in S} \|c\|_{\text{op}}$ .

**Strong sampling set.** Given any ring  $\mathcal{R}$ , a set  $\mathcal{C}$  is a *strong sampling set* if for all  $c_1 \neq c_2 \in \mathcal{C}$  the difference  $c_1 - c_2$  is invertible. For example, any field embedded in the ring is a strong sampling set. We say that  $\mathcal{C}$  is a  $\kappa_{\text{nu}}$ -approximate strong sampling set if for all  $c_0 \neq c_1$  sampled from  $\mathcal{C}$  the difference  $c_0 - c_1$  is either invertible or a zero divisor with probability at most  $\kappa_{\text{nu}}$  over the sampling of  $c_0, c_1$  according to  $\mathcal{C}$ . We say that  $\mathcal{C}$  is of norm  $\gamma$  if  $\|c\|_{\text{op}} \leq \gamma$  for all  $c \leftarrow \mathcal{C}$ .

In Section B we discuss how to instantiate such distributions in cyclotomic rings. We remark that our instantiation of approximate strong sampling set is of independent interest and can be used in other contexts.

**Sum-checks over  $\mathbb{F}_{q^e}$ .** For a polynomial  $f \in \mathbb{F}_{q^e}[X_0, \dots, X_{k-1}]$  with individual degree  $\leq \ell$ , and a value  $s \in \mathbb{F}_{q^e}$ , there is a public-coin interactive protocol that reduces the checking of  $s \stackrel{?}{=} \sum_{\mathbf{z} \in \{0, 1\}^k} f(\mathbf{z})$  to checking whether  $f(\mathbf{r}) \stackrel{?}{=} v$  for  $\mathbf{r} \xleftarrow{\$} \mathbb{F}_{q^e}^k$  and  $v \in \mathbb{F}_{q^e}$ . The protocol is perfectly complete, with soundness error at most  $\frac{k\ell}{q^e}$ .

**Sum-checks over  $\mathcal{R}_q$  (resp.,  $\mathcal{R}_{q^e}$ ).** We can also run the sum-check protocol over  $\mathcal{R}_q$  (resp.,  $\mathcal{R}_{q^e}$ ) instead of  $\mathbb{F}_{q^e}$  for a polynomial  $f \in \mathcal{R}_q[X_0, \dots, X_{k-1}]$  (resp.,  $f \in \mathcal{R}_{q^e}[X_0, \dots, X_{k-1}]$ ) with individual degree  $\leq \ell$ . The key observation is that  $\mathcal{R}_q \cong (\mathbb{F}_{q^e})^{\varphi/e}$  (resp.,  $\mathcal{R}_{q^e} \cong (\mathbb{F}_{q^e})^{\varphi}$ ) via NTT transformation. Therefore, sum-check over  $\mathcal{R}_q$  (resp.  $\mathcal{R}_{q^e}$ ) can be viewed as  $\varphi/e$  (resp.  $\varphi$ ) parallel sum-checks over  $\mathbb{F}_{q^e}$ . Those sum-checks are immediately batched together into a single sum-check over  $\mathbb{F}_{q^e}$ . The protocol is perfectly complete and has a soundness error at most  $\frac{k\ell+\varphi/e}{q^e}$  (resp.  $\frac{k\ell+\varphi}{q^e}$ ), accounting for the increased soundness error due to the (structured) batching.

**Lemma 3 ([BCPS18] Theorem 4.2).** *Let  $\mathcal{R}$  be any ring,  $\mathcal{C}$  be a strong sampling set and  $f \in \mathcal{R}[X_0, \dots, X_{f-1}]$ . Then  $\Pr(f(r) = 0 | r \xleftarrow{\$} \mathcal{C}^n) \leq \frac{\deg f}{|\mathcal{C}|}$ , where  $\deg f$  is the total degree of  $f$ .*

**Polynomial zero bounds over rings.** Over a ring, if  $C \subset R$  is a strong sampling set and  $f \in R[X_0, \dots, X_{\ell-1}]$  is nonzero with per-variable degrees  $(d_0, \dots, d_{\ell-1})$ , then  $\Pr_{r \leftarrow C^e}[f(r) = 0] \leq \sum_i d_i / |C|$  [BCPS18]. We use this *ring* bound for batching/extension where challenges lie in  $C \subset R_q$ . In contrast, the range test lives over the field  $\mathbb{Z}_q$ , so its per-repetition error is  $D/q$  (Sec. 2.2).

We use the ring bound over  $C \subset R_q$  for batching/extension, and the field bound  $D/q$  for the range test (Sections 3 and 4).

**Principal Linear Relation.** We consider the following principal linear relation:

$$\Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [k]}, a, n, m, B}^{\text{lin}} := \left\{ \begin{array}{c} ((\mathbf{r}_i)_{i \in [k]}, (\mathbf{b}_i)_{i \in [n]}, \mathbf{y}), \mathbf{w} : \\ \left( \mathbf{M}_i \in \mathcal{R}_q^{m_i \times m}, \mathbf{r}_i \in \mathcal{R}_q^{\log m_i} \right)_{i \in [k]}, (\mathbf{b}_i \in \mathcal{R}_q^{\log m})_{i \in [n]}, \\ \mathbf{A} \in \mathcal{R}_q^{a \times m}, \mathbf{y} = \begin{pmatrix} \bar{\mathbf{y}} \in \mathcal{R}_q^a \\ \mathbf{y} \in \mathcal{R}_q^{k+n} \end{pmatrix}, \mathbf{w} \in \mathcal{R}_q^m, \|\mathbf{w}\| \leq B \\ \begin{pmatrix} \mathbf{A} \\ \text{tensor}(\mathbf{r}_0)^T \mathbf{M}_0 \\ \vdots \\ \text{tensor}(\mathbf{r}_{k-1})^T \mathbf{M}_{k-1} \\ \text{tensor}(\mathbf{b}_0)^T \\ \vdots \\ \text{tensor}(\mathbf{b}_{n-1})^T \end{pmatrix} \mathbf{w} = \mathbf{y} \bmod q \end{array} \right\}. \quad (6)$$

In words, an instance of the relation consists of  $k$  matrices  $(\mathbf{M}_i)_{i \in [k]}$  with  $m_i$  rows and  $m$  columns,  $k$  vectors  $(\mathbf{r}_i)_{i \in [k]}$  of length  $\log m_i$ ,  $n$  vectors  $(\mathbf{b}_i)_{i \in [n]}$  of length  $\log m$ , a matrix  $\mathbf{A}$  with  $a$  rows and  $m$  columns, and a vector  $\mathbf{y}$  of length  $a + k + n$ . A witness to the relation is a vector  $\mathbf{w}$  of length  $m$  with the norm constraint  $\|\mathbf{w}\| \leq B$ .

The relation states that the witness  $\mathbf{w}$  is a short solution to three families of constraints defined by (i)  $\mathbf{A}$ , which is supposed to be random. This part is used to reduce a forgery to a short solution of the SIS problem. (ii)  $(\mathbf{M}_i)_{i \in [k]}$  and  $(\mathbf{r}_i)_{i \in [k]}$ , which are used to express different constraints imposed by fixed matrices  $(\mathbf{M}_i)_{i \in [k]}$  on the witness  $\mathbf{w}$ . The vectors  $(\mathbf{r}_i)_{i \in [k]}$  are used to batch the rows of the matrices  $(\mathbf{M}_i)_{i \in [k]}$ . Those constraints are used as an output of the reduction from R1CS/CCS. (iii)  $(\mathbf{b}_i)_{i \in [n]}$ , which are used to express simple constraints used in various stages of the protocol, i.e. as evaluation claims as an output of the sum-check protocol. For brevity, we will often omit the parameters of the relation, which are obvious from the context, and write e.g.  $\Xi_B^{\text{lin}}$ .

**Slack.** We also define the following auxiliary “slacked” relations  $\Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [k]}, a, n, m, B, \varrho}^{\text{lin-slack}}$ , which will be useful in the security proofs. The slacked relation is the same as the principal relation, except that the witness  $\mathbf{w}$  is divided by a scalar  $s \in \mathcal{R}_q^\times$  with norm  $\|s\| \leq \varrho$  and the norm constraint is applied to  $\mathbf{w}$  instead of  $\mathbf{w}/s$ . The precise definition is deferred to Section A.

## Range Test

$$\Pi_b^{\text{range}} : \left( \left( (\mathbf{r}_i)_{i \in [k]}, (\mathbf{b}_i)_{i \in [n]}, \mathbf{y} \right), \mathbf{w} \right) \in \Xi_{n,b}^{\text{lin}} \rightarrow \Xi_{n+1,b}^{\text{lin}}$$

1. Prover defines  $f := \text{MLE}[\text{cf}(\mathbf{w})] \in \mathbb{Z}_q[X_0, \dots, X_{\ell-1}]$  with  $\ell = \lceil \log(m\varphi) \rceil$ .  
Let  $\text{tensor}(\cdot) \in \mathbb{F}_{q^\varphi}^{m\varphi}$  denote the multilinear evaluation tensor such that  $\langle \text{tensor}(\mathbf{z}), \text{cf}(\mathbf{w}) \rangle = \text{MLE}[\text{cf}(\mathbf{w})](\mathbf{z})$  for all  $\mathbf{z} \in \mathbb{F}_{q^\varphi}^\ell$ . We view  $\text{tensor} : \mathbb{F}_{q^\varphi}^\ell \rightarrow \mathbb{F}_{q^\varphi}^{m\varphi}$  as the standard Boolean-ML extension tensor.
2. The verifier samples  $\boldsymbol{\eta} = (\eta_0, \eta_1, \dots, \eta_{\ell-1}) \leftarrow \mathbb{F}_{q^\varphi}$  and sets  $\omega(X) := \text{eq}(X; \boldsymbol{\eta})$ .
3. Prover sets  $\hat{f}(X) := \prod_{j=-b}^b (f(X) - j) \cdot \omega(X) \in \mathbb{F}_{q^\varphi}[X_0, \dots, X_{\ell-1}]$ .
4. The parties run sum-check over  $\mathbb{F}_{q^\varphi}$ , reducing  $\sum_{\mathbf{z} \in \{0,1\}^\ell} \hat{f}(\mathbf{z}) \stackrel{?}{=} 0$  to  $\hat{f}(\mathbf{u}) \stackrel{?}{=} s$ , where  $\mathbf{u}$  is the challenge vector sampled by the verifier and  $s \in \mathbb{F}_{q^\varphi}$  is the claimed leaf value sent by the prover.
5. Prover sets  $\tilde{t} := \langle \mathbf{u}', \mathbf{w} \rangle \in \mathcal{R}_{q^\varphi}$  for  $\mathbf{u}' := \text{cf}_{\bar{\vee}}^{-1}(\text{tensor}(\mathbf{u}))$  and sends it to the verifier (here  $\text{cf}_{\bar{\vee}}^{-1}(\text{tensor}(\mathbf{u})) \in \mathcal{R}_{q^\varphi}^m$  so the inner product lies in  $\mathcal{R}_{q^\varphi}$ ).
6. Verifier computes  $t := \text{Trace}(\tilde{t}) \in \mathbb{F}_{q^\varphi}$  and checks  $s \stackrel{?}{=} \omega(\mathbf{u}) \cdot \prod_{j=-b}^b (t - j)$ . By Lemma 1 (dual-basis trace),  $\text{Trace}(\langle \text{cf}_{\bar{\vee}}^{-1}(\text{tensor}(\mathbf{u})), \mathbf{w} \rangle) = \text{MLE}[\text{cf}(\mathbf{w})](\mathbf{u})$ . Since  $\text{Trace}(\tilde{t}) = \text{MLE}[\text{cf}(\mathbf{w})](\mathbf{u}) = f(\mathbf{u})$ , the leaf check equals  $\hat{f}(\mathbf{u}) \stackrel{?}{=} s$ .
7. Prover and verifier output:  $\left( \left( (\mathbf{r}_i)_{i \in [k]}, \left( (\mathbf{b}_i)_{i \in [n]}, \mathbf{u}' \right), \left( \begin{smallmatrix} \mathbf{y} \\ \tilde{t} \end{smallmatrix} \right) \right), \mathbf{w} \right) \in \Xi_{n+1,b}^{\text{lin}}$ .

**Fig. 1.** Range test protocol  $\Pi_b^{\text{range}}$ .

Further, we define the “SIS-break” relation, which is used to reduce a forgery to a short solution of the SIS problem. The relation is simply a type of  $\Xi^{\text{lin}}$  with no additional constraints, i.e.  $k = n = 0$  and the image is  $\mathbf{0}$ . The precise definitions of “slacked” and “SIS-break” relations are deferred to Section A.

**Reduction of Knowledge.** The (standard) notion of reduction of knowledge is deferred to Section A.

# 4 Range Test

In this section, we present a protocol for testing that a committed vector  $\mathbf{w} \in \mathcal{R}_q^m$  satisfies  $\|\mathbf{w}\| \leq b$ , i.e., its coefficients lie in the range  $[-b, b]$ . The protocol is presented in Fig. 1.

**Theorem 1 (KS of Range).** *Let  $q$  be a prime,  $\mathcal{R}$  be a cyclotomic ring with conductor  $\mathfrak{f}$ ,  $b, \tilde{b}, \varrho, z \in \mathbb{N}$  and  $\mathbf{A} \in \mathcal{R}_q^{a \times m}$ ,  $\varphi := \varphi(\mathfrak{f})$ . Assume, for convenience, that  $m$  and  $\varphi$  are powers of two (used only for NTT/indexing).  $\Pi_b^{\text{range}}$  is perfectly correct:*

$$\Xi_{\mathbf{A}, a, n, b}^{\text{lin}} \rightarrow \Xi_{\mathbf{A}, a, n+1, b}^{\text{lin}}$$

$\Pi_b^{\text{range}}$  is knowledge sound with knowledge error  $\kappa := \ell(2b+2)/q^\varphi$  for  $\ell = \lceil \log(m\varphi) \rceil$ .

$$\Xi_{\mathbf{A}, a, n, b}^{\text{lin}} \cup \Xi_b^{\text{sis}} \leftarrow \Xi_{\mathbf{A}, n+1, \tilde{b}, \varrho}^{\text{lin-slack}}$$

for  $\tilde{b} = 2\tilde{b}\varrho$ . The communication complexity of the protocol is 1  $\mathcal{R}_{q^\varphi}$  element and  $(2b+2)\ell + 1$   $\mathbb{F}_{q^\varphi}$  elements.

*Proof. Correctness.* Let  $f := \text{MLE}[\text{cf}(\mathbf{w})] : \mathbb{Z}_q^\ell \rightarrow \mathbb{Z}_q$  with  $\ell = \lceil \log(m\varphi) \rceil$  lifted implicitly to  $\mathbb{F}_{q^\varphi}^\ell \rightarrow \mathbb{F}_{q^\varphi}$ . Define  $\hat{f}(X) := \omega(X) \cdot \prod_{j \in [-b, b]} (f(X) - j)$  (assuming  $b < q$ ). Then  $t = \text{Trace}(\tilde{t})$  by

linearity of trace (Lemma 1), and for all  $\mathbf{z} \in \{0, 1\}^\ell$  we have  $\hat{f}(\mathbf{z}) = \omega(\mathbf{z}) \cdot \prod_{j \in [-b, b]} (f(\mathbf{z}) - j)$ . Hence the verifier checks  $s = \omega(\mathbf{u}) \cdot \prod_{j=-b}^b (t - j)$  at the leaf, so the test is correct when  $\mathbf{cf}(\mathbf{w}) \in [-b, b]^{m\varphi}$ .

*Knowledge soundness.* The extractor runs the prover  $\mathcal{P}^*$  on random challenges. If the prover rejects, extractor fails. Otherwise, it rewinds the prover (possibly many times) with fresh challenges to obtain  $(\mathbf{w}^*, s^*)$  and  $(\mathbf{w}', s')$ .

If  $\mathbf{v}^* := \mathbf{w}^*/s^* \neq \mathbf{v}' := \mathbf{w}'/s'$ , then  $\mathbf{A}(\mathbf{w}^*s' - \mathbf{w}'s^*) = \mathbf{0}$  and we output a  $\Xi^{\text{sis}}$  witness with norm  $\leq 2\tilde{b}\gamma\varrho$ . If  $\mathbf{v}^*$  is a valid witness to  $\Xi_{\mathbf{A}, a, n, b}^{\text{lin}}$ , the extractor outputs it. Otherwise  $\mathbf{v}^* = \mathbf{v}'$  while  $\mathbf{v}^*$  does not satisfy  $\Xi_{\mathbf{A}, a, n, b}^{\text{lin}}$ . We observe that the challenges for the second transcript are independent of  $\mathbf{v}^*$ , yet the sum-check test passes for  $\mathbf{v}^*$  with those fresh challenges. Since  $f$  is multilinear and  $\deg_{X_i} \omega \leq 1$ , each variable appears in  $\hat{f}$  with degree at most  $2b + 2$ . Let  $D := \sum_{i \in [\ell]} \deg_{X_i} \hat{f} \leq \ell(2b + 2)$ . By soundness of sum-check and Schwartz-Zippel over  $\mathbb{F}_{q^\varphi}$ , the acceptance probability is at most  $\kappa := \ell(2b + 2)/q^\varphi$ , which is the knowledge error of the protocol.

*Extractor efficiency.* To find accepting transcripts when sampling random challenges requires  $1/\epsilon$  tries in expectation. Since the extractor only rewinds if the initial uniform challenge was successful, and then samples challenges uniformly at random, it follows by a standard argument that  $\epsilon \cdot (1/\epsilon) = 1$  rewinds are required in expectation. Hence, the extractor is expected polynomial-time.

*Communication.* In sum-check over  $\ell$  variables with  $\deg_{X_i} \hat{f} \leq 2b + 2$ , the prover sends at most  $2b + 2$  field elements per round (the coefficients of the univariate polynomial of degree  $2b + 2$ , including the folklore optimisation to ignore the constant term), totaling  $(2b + 2)\ell$  field elements, plus the final claim  $s \in \mathbb{F}_{q^\varphi}$ , and one ring element  $\tilde{t} \in \mathcal{R}_{q^\varphi}$ .  $\square$

# 5 Extension Commitment

In this section, we present the next building block of our folding scheme: the extension commitment. The extension commitment is a method to commit to the decomposition of the witness of the input relation. Contrary to popular methods, we decompose the witness “vertically,” i.e., it remains a single linear relation, thereby limiting communication overhead. The extension commitment is presented in Fig. 2. This decomposition is particularly important because the range test yields linear computational and communication overhead in the  $\ell_\infty$  bound.

**Theorem 2.** *Let  $q$  be a prime,  $\mathcal{R}$  be a cyclotomic ring with a conductor  $\mathfrak{f}$ ,  $b, B, k, n, \tilde{B}, \varrho \in \mathbb{N}$ ,  $\mathbf{A} \in \mathcal{R}_q^{a \times m}$ ,  $\mathbf{R} \in \mathcal{R}_q^{a' \times m\ell}$ . Let  $\mathcal{C}$  be a strong sampling set with  $\mathcal{C} \subseteq \mathbb{F}_{q^\varphi}$  and  $b \geq 2$ . The protocol  $\Pi_{b, \mathcal{C}}^{\text{ext}}$  is perfectly correct:*

$$\Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [k]}, a, n, m, B}^{\text{lin}} \rightarrow \Xi_{\mathbf{R}, (\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', n, m\ell, b}^{\text{lin}}$$

and knowledge sound with knowledge-error  $\ell_C/|\mathcal{C}|$  where  $\ell_C := \lceil \log_2 a \rceil$ :

$$\Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [k]}, a, n, m, B}^{\text{lin}} \cup \Xi_{\mathbf{R}, a', m\ell, 2b}^{\text{sis}} \leftarrow \Xi_{\mathbf{R}, a', n, m\ell, b}^{\text{lin}}$$

The communication complexity of the protocol is  $a'$   $\mathcal{R}_q$  elements.

*Proof. Correctness:* The linear equality follows from the definition in Step 2 and the bound  $\|\mathbf{v}\|_\infty \leq b$  from the fact that  $\mathbf{v}$  is a concatenation of the base- $b$  decomposition of  $\mathbf{w}$ .

*Knowledge soundness:* For knowledge soundness, we construct explicitly the extractor  $\mathcal{E}$ . Without loss of generality, assume that the prover is deterministic. Suppose the extractor is given an instance  $(\text{pp}, \mathbf{y})$  and a prover  $\mathcal{P}^*$  which succeeds with probability  $\epsilon$ .

## Extension commitment

$$\Pi_{b,C}^{\text{ext}} : \left( ((\mathbf{r}_i)_{i \in [k]}, (\mathbf{b}_i)_{i \in [n]}, \mathbf{y}), \mathbf{w} \right) \in \Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [k]}, a, n, m, B}^{\text{lin}} \rightarrow \Xi_{\mathbf{R}, (\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', n, m\ell, b}^{\text{lin}}$$

1. The prover splits the witness:  $\mathbf{v}^T = (\mathbf{w}_0^T, \dots, \mathbf{w}_{\ell-1}^T)$ , where  $\mathbf{w}_i$  are such that  $\|\mathbf{w}_i\|_\infty \leq b$  for all  $i \in [\ell]$  and  $\mathbf{w} = \sum_{i=0}^{\ell-1} \mathbf{w}_i b^i$ .
2. The prover sends the extended commitment  $\mathbf{t} := \mathbf{R}\mathbf{v} \in \mathcal{R}_q^{a'}$  to the verifier.
3. The verifier samples  $\widehat{\mathbf{c}} \leftarrow \mathcal{C}^{\ell_C}$  and sets  $\mathbf{c} := \mathbf{tensor}(\widehat{\mathbf{c}}) \in \mathcal{R}_{q^e}^a$ .
4. Let
  - (i)  $\widehat{\mathbf{b}}_i^T := ((2b)^0, (2b)^1, \dots, (2b)^{\ell-1}) \otimes \mathbf{b}_i^T \in \mathcal{R}_{q^e}^{[\log m] + \ell} \quad \forall i \in [k]$ ,
  - (ii)  $\widehat{\mathbf{M}}_i := ((2b)^0, (2b)^1, \dots, (2b)^{\ell-1}) \otimes \mathbf{M}_i \in \mathcal{R}_q^{m_i \times m\ell} \quad \forall i \in [k]$ ,
  - (iii)  $\widehat{\mathbf{M}}_k := ((2b)^0, (2b)^1, \dots, (2b)^{\ell-1}) \otimes \mathbf{A} \in \mathcal{R}_q^{a \times m\ell}$ ,
The prover and verifier output the augmented instance

$$\left( ((\mathbf{r}_i)_{i \in [k]}, \mathbf{c}), (\widehat{\mathbf{b}}_i)_{i \in [n]}, \widehat{\mathbf{y}}), \mathbf{v} \right) \in \Xi_{\mathbf{R}, (\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', n, m\ell, b}^{\text{lin}}$$

$$\text{for } \widehat{\mathbf{y}}^T := (\mathbf{t}^T, y_a, \dots, y_{a+k-1}, \langle \mathbf{c}, (y_0, \dots, y_{a-1}) \rangle, y_{a+k}, \dots, y_{a+k+n-1}).$$

**Fig. 2.** Extension commitment protocol  $\Pi^{\text{ext}}$ . Here,  $\ell = \lceil \log_{2b} 2B \rceil$  and  $\ell_C := \lceil \log a \rceil$ .

Let  $\ell := \lceil \log_{2b} 2B \rceil$ . First the extractor runs  $\mathcal{P}^*$  and with probability  $\epsilon$  receives an instance-witness pair

$$\left( ((\mathbf{r}_i)_{i \in [k]}, \mathbf{c}), (\widehat{\mathbf{b}}_i)_{i \in [n]}, \widehat{\mathbf{y}}), \mathbf{v}^* \right) \in \Xi_{\mathbf{R}, (\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', n, m\ell, b}^{\text{lin}}$$

and  $\|\mathbf{v}^*\|_\infty < b$ , where  $\mathbf{c}^*$  is the vector derived from the verifier's challenge vector as in step 3. If the prover does not succeed, the extractor aborts.

If the extractor does not abort, it calculates  $\mathbf{w}^* = \sum_{i \in [\ell]} \mathbf{v}_i^* b^i$ . If  $(\mathbf{A}) \mathbf{w}^* = \overline{\mathbf{y}} \bmod q$ , where  $\overline{\mathbf{y}}^T := (y_i)_{i \in [a]}$  then the extractor outputs  $\mathbf{w}^*$ .

Otherwise the extractor runs  $\mathcal{P}^*$  again as many times it needs to get another accepting transcript with a challenge  $\widehat{\mathbf{c}}'$  (and set  $\mathbf{c}' := \mathbf{tensor}(\widehat{\mathbf{c}}') \in \mathbb{F}_{q^e}^a$ , and  $\widehat{\mathbf{c}}' := \mathbf{cf}_V^{-1}(\mathbf{c}') \in \mathcal{R}_{q^e}^a$ ) and witness  $\mathbf{v}'$ . If  $\mathbf{v}^* \neq \mathbf{v}'$ , then the extractor finds a witness for  $\Xi_{\mathbf{R}, a', m\ell, 2b}^{\text{sis}}$  since  $\mathbf{R}\mathbf{v}^* = \mathbf{R}\mathbf{v}' = \mathbf{t}$  in the public instance, thus  $\mathbf{R}(\mathbf{v}^* - \mathbf{v}') = \mathbf{0}$  and  $\|\mathbf{v}^* - \mathbf{v}'\|_\infty \leq 2b$ . If  $\mathbf{v}^* = \mathbf{v}'$ , then we apply the ring zero bound over product sets Lemma 3 to the equality  $\langle \widehat{\mathbf{c}}', ((2b)^0, (2b)^1, \dots, (2b)^{\ell-1}) \otimes \mathbf{A} \mathbf{v}^* - \mathbf{y} \rangle = 0 \bmod q$ . Since  $\widehat{\mathbf{c}}'$  is uniform in  $\mathcal{C}^{\ell_C}$  and  $\mathbf{c}' = \mathbf{tensor}(\widehat{\mathbf{c}}')$  is multilinear with per-variable degree 1, the left-hand side is a nonzero polynomial in  $\widehat{\mathbf{c}}'$  of total degree at most  $\ell_C$  unless  $((2b)^0, \dots, (2b)^{\ell-1}) \otimes \mathbf{A} \mathbf{v}^* = \mathbf{y} \bmod q$ . Hence, by Lemma 3,

$$\Pr_{\widehat{\mathbf{c}}' \leftarrow \mathcal{C}^{\ell_C}} \left[ \begin{array}{l} \langle \widehat{\mathbf{c}}', ((2b)^0, (2b)^1, \dots, (2b)^{\ell-1}) \otimes \mathbf{A} \mathbf{v}^* - \mathbf{y} \rangle = 0 \bmod q \\ \wedge ((2b)^0, \dots, (2b)^{\ell-1}) \otimes \mathbf{A} \mathbf{v}^* \neq \mathbf{y} \bmod q \end{array} \right] \leq \ell_C / |\mathcal{C}|.$$

Therefore, the knowledge error is  $\kappa = \ell_C / |\mathcal{C}|$ .

*Runtime of the extractor:* If the prover succeeds with probability  $\epsilon$ , the expected number of prover invocations is  $O(1/\epsilon)$  by the standard forking analysis; hence, the extractor runs in expected polynomial time.

*Communication complexity:* The communication complexity of the protocol is  $a' \mathcal{R}_q$  elements, which is the size of the vector  $\mathbf{t}$  sent by the prover.  $\square$

# Folding Scheme

$$\Pi_{b,\mathcal{D},\mathcal{C}}^{\text{fs}} : \left( \begin{array}{c} ((\mathbf{r}_i)_{i \in [k]}, \mathbf{b}, \mathbf{y}, \mathbf{v}) \in \Xi_{\mathbf{R},(\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', 1, m \log_{2b} 2B, \beta}^{\text{lin}} \\ \left( \begin{array}{c} ((\mathbf{r}'_{i,j})_{i \in [k]}, (\mathbf{b}'_{i,j})_{i \in [n]}, \mathbf{y}'_j, \mathbf{w}'_j)_{j \in [L]} \in (\Xi_{\mathbf{A},(\mathbf{M}_i)_{i \in [k]}, a', n, m, B}^{\text{lin}})^L \\ \rightarrow \Xi_{\mathbf{R},(\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', 1, m \log_{2b} 2B, \beta + Lb\gamma}^{\text{lin}} \end{array} \right) \end{array} \right)$$

1. Prover and verifier compute for all  $j \in [L]$ : // see Fig. 2

$$((\mathbf{r}''_{i,j})_{i \in [k+1]}, (\mathbf{b}'_{i,j})_{i \in [n]}, \mathbf{t}'_j, \mathbf{v}'_j) \leftarrow \Pi_{b,\mathcal{C}}^{\text{ext}}(((\mathbf{r}'_{i,j})_{i \in [k]}, (\mathbf{b}'_{i,j})_{i \in [n]}, \mathbf{y}'_j, \mathbf{w}'_j)).$$

2. Prover and verifier compute for all  $j \in [L]$ : // see Fig. 1

$$((\mathbf{r}''_{i,j})_{i \in [k+1]}, (\mathbf{b}''_{i,j})_{i \in [n+1]}, \mathbf{t}'_j, \mathbf{v}'_j) \leftarrow \Pi_b^{\text{range}}(((\mathbf{r}''_{i,j})_{i \in [k+1]}, (\mathbf{b}'_{i,j})_{i \in [n]}, \mathbf{t}'_j, \mathbf{v}'_j)).$$

3. Verifier samples  $\mathbf{d} \leftarrow \mathbb{F}_{q^e}^{\lceil \log \varphi(2+k+L(2+n+k)) \rceil}$ .

4. Let  $\tilde{m} := m \log_{2b} 2B$  and  $\tilde{m}_i := m_i \log_{2b} 2B$  for  $i \in [k+1]$ . Prover and verifier express linear equalities concerning input relations as sum-check instances:

- (a)  $\sum_{\mathbf{z} \in \{0,1\}^{\log \tilde{m}_i}} \text{MLE}[\widehat{\mathbf{M}}_i \mathbf{v}'_j](\mathbf{z}) \text{eq}(\mathbf{z}; \mathbf{r}''_{i,j}) = t'_{j,a'+i}, \quad i \in [k+1] \ j \in [L],$
- (b)  $\sum_{\mathbf{z} \in \{0,1\}^{\log \tilde{m}_i}} \text{MLE}[\widehat{\mathbf{M}}_i \mathbf{v}](\mathbf{z}) \text{eq}(\mathbf{z}; \mathbf{r}_i) = y_{a'+i}, \quad i \in [k+1],$
- (c)  $\sum_{\mathbf{z} \in \{0,1\}^{\log \tilde{m}}} \text{MLE}[\mathbf{v}'_j](\mathbf{z}) \text{eq}(\mathbf{z}; \mathbf{b}''_{i,j}) = t'_{j,a'+k+1+i}, \quad i \in [n+1] \ j \in [L],$
- (d)  $\sum_{\mathbf{z} \in \{0,1\}^{\log \tilde{m}}} \text{MLE}[\mathbf{v}](\mathbf{z}) \text{eq}(\mathbf{z}; \mathbf{b}) = y_{a'+k+1},$

Then, they batch the sum-check claims<sup>a</sup> with  $\mathbf{d}$  and execute the sum-check protocol (over  $\mathbb{F}_{q^e}$  NTT slots of  $\mathcal{R}_{q^e}$ ) to reduce them to claims over a shared random point, i.e.,  $((\widehat{\mathbf{r}}_i)_{i \in [k]}, \widehat{\mathbf{r}}, \widehat{\mathbf{y}}, \mathbf{v}) \in \Xi_{\mathbf{R},(\widehat{\mathbf{M}}_i)_{i \in [k+1]}}^{\text{lin}}$  and

$$((\widehat{\mathbf{r}}_i)_{i \in [k]}, \widehat{\mathbf{r}}, \widehat{\mathbf{y}}'_j, \mathbf{v}'_j) \in \Xi_{\mathbf{A},(\mathbf{M}_i)_{i \in [k]}}^{\text{lin}} \text{ for } j \in [L].$$

The new evaluation claims  $\widehat{\mathbf{y}}[a', \widehat{\mathbf{y}}]$  and  $\widehat{\mathbf{y}}'_j[a', \widehat{\mathbf{y}}'_j]$  (over  $\mathcal{R}_{q^e}$ ) are sent to the verifier.

5. Verifier sends a short folding challenge  $\mathbf{s} \leftarrow \mathcal{D}^L$ .

6. Prover and verifier output:

$$\left( \left( (\widehat{\mathbf{r}}_i)_{i \in [k]}, \widehat{\mathbf{r}}, \widehat{\mathbf{y}} + \sum_{j \in [L]} s_j \widehat{\mathbf{y}}'_j \right), \mathbf{v} + \sum_{j \in [L]} s_j \mathbf{v}'_j \right) \in \Xi_{\mathbf{R},(\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', 1, \tilde{m}, \beta + Lb\gamma}^{\text{lin}}$$

where  $\gamma$  is the expansion factor of the challenge set  $\mathcal{D}$ .

<sup>a</sup> Batching sum-check claims with different numbers of variables requires padding functions with fewer variables using unused auxiliary variables and later erasing the corresponding coordinates from the output evaluation point.

Fig. 3. Folding scheme Cyclo.

# 6 Folding Scheme: Cyclo

Equipped with the range test and extension commitment, we now present the complete folding scheme Cyclo. We start by defining the “accumulator” relation family: for any  $\beta \in \mathbb{N}$ ,  $\Xi_{\text{acc},\beta}^{\text{lin}} := \Xi_{\mathbf{R},(\widehat{\mathbf{M}}_i)_{i \in [k+1]}, a', 1, m \log_{2b} 2B, \beta}^{\text{lin}}$ . We trivially initiate the accumulator by setting  $((\mathbf{r}_i)_{i \in [k+1]}, \mathbf{b}, \mathbf{y}, \mathbf{v}) \in \Xi_{\text{acc},\beta}^{\text{lin}}$  so that  $(\mathbf{r}_i)_{i \in [k+1]}, \mathbf{b}, \mathbf{y}, \mathbf{v}$  are all zero vectors. We then define the folding scheme as follows; see Fig. 3. The folding scheme could be “morally” viewed as a four-step process: first, we extend the witness of each instance using the extension commitment, then we run the range test on each extended witness, then we “unify” all the relations into a single relation using the sum-check protocol, and finally we fold the witnesses using random linear combinations.

**Theorem 3.** Let  $q$  be a prime,  $\mathcal{R}$  be a cyclotomic ring with a conductor  $f$ ,  $b, B \in \mathbb{N}$ ,  $\mathbf{A} \in \mathcal{R}_q^{a \times m}$ ,  $\mathbf{R} \in \mathcal{R}_q^{a' \times m \log_{2b} 2B}$ ,  $\varphi := \varphi(f)$ . Let  $\mathcal{C} \subseteq \mathcal{R}_q$  be a strong sampling set and  $\mathcal{D} \subseteq \mathcal{R}_q$  be a  $\kappa_{\text{nu}}$ -approximate strong sampling set. Let  $\gamma$  be the operator norm of  $\mathcal{D}$ .

1. The protocol  $\Pi_{b, \mathcal{D}, \mathcal{C}}^{\text{fs}}$  is perfectly correct:

$$\Xi_{\text{acc}, \beta}^{\text{lin}} \times (\Xi_{a, n, m, B}^{\text{lin}})^L \rightarrow \Xi_{\text{acc}, \beta + Lb\gamma}^{\text{lin}}.$$

2. It is knowledge sound with knowledge error  $\kappa \leq L/|\mathcal{D}| + (\ell_0 + \ell_1)/q^e + L\ell_1(2b+2)/q^e + L\ell_C/|\mathcal{C}| + L\kappa_{\text{nu}}$ , where  $\ell_0 := \lceil \log \varphi(2 + k + L(2 + n + k)) \rceil$  and  $\ell_1 := \lceil \log(m\varphi \log_{2b} 2B) \rceil$ ,  $\ell_C = \lceil \log(a) \rceil$  for

$$\Xi_{\mathbf{R}, 2\bar{\beta}\delta}^{\text{sis}} \cup \left( \Xi_{\text{acc}, \bar{\beta} + Lb\gamma}^{\text{lin}} \times (\Xi_{a, n, m, B}^{\text{lin}})^L \right) \leftarrow \Xi_{\text{acc}, \bar{\beta}}^{\text{lin}},$$

where  $\bar{\beta} = \hat{\beta}(2\gamma)^L + L \cdot 2\hat{\beta}(2\gamma)^{L-1}$ ,  $\delta = (2\gamma)^L$ .

3. Its communication complexity (prover to verifier) is  $La' + L$  elements in  $\mathcal{R}_q$ ,  $(k+2) \cdot (L+1)$  elements in  $\mathcal{R}_{q^e}$ , Additionally, there are  $2\lceil \log m\varphi(\log_{2b} 2B) \rceil$   $\mathbb{F}_{q^e}$  elements and  $L(2b+2)\lceil \log(m\varphi(\log_{2b} 2B)) \rceil$   $\mathbb{F}_{q^e}$  elements.

In the proof of Theorem 3, we use the following lemma.

**Lemma 4 (Coordinate-wise forking for CWSS).** Let  $\mathbf{s} \in \mathcal{D}^L$  be sampled uniformly and suppose a prover convinces the verifier for  $\mathbf{R}'\hat{\mathbf{v}} = \mathbf{Y}'\binom{1}{\mathbf{s}} \bmod q$  with probability  $\varepsilon$ . By rewinding one coordinate at a time and (in ROM) reprogramming the hash so that only the  $i$ -th coordinate is resampled  $s'_i \leftarrow \mathcal{D}$ , keeping the other  $L-1$  coordinates as in  $\mathbf{s}^{(L)}$ , we obtain with probability at least  $\varepsilon - L/|\mathcal{D}|$  a set of  $L+1$  accepting transcripts with challenges  $\mathbf{s}^{(0)}, \dots, \mathbf{s}^{(L)}$ . Setting  $\Delta_i := s'_i - s_i^{(L)}$ , subtracting the  $i$  and  $L$  transcripts isolates, for all  $i \in [L]$ ,  $\mathbf{R}'_i(\hat{\mathbf{v}}^{(i)} - \hat{\mathbf{v}}^{(L)}) = \mathbf{Y}'_i \Delta_i \bmod q$ . Except with probability at most  $L/|\mathcal{D}| + L\kappa_{\text{nu}}$ , all  $\Delta_i$  are units (where  $\kappa_{\text{nu}} := \Pr[\Delta_i \notin \mathcal{R}_q^\times]$  is the per-coordinate non-unit probability and we apply a union bound over  $i \in [L]$ ); moreover  $\|\Delta_i\|_{\text{op}} \leq \|s'_i\|_{\text{op}} + \|s_i^{(L)}\|_{\text{op}} \leq 2\gamma$ , hence the slack uses  $2\gamma$ .

*Proof (Sketch).* Use domain-separated random-oracle tags so the  $L$  coordinates of  $\mathbf{s}$  are independent of each other and of  $z$ . Fix an accepting execution; it occurs with probability  $\varepsilon$ . For each  $i \in [L]$ , rewind and reprogram only the  $i$ -th query to the RO to resample  $s'_i \leftarrow \mathcal{D}$  while leaving all other answers unchanged; acceptance is preserved except with probability  $1/|\mathcal{D}|$ , so we obtain  $L+1$  accepting transcripts with probability at least  $\varepsilon - L/|\mathcal{D}|$ . Subtract the baseline transcript (indexed  $L$ ) from the  $i$ -th transcript; all shared rows cancel and we get  $\mathbf{R}'_i(\hat{\mathbf{v}}^{(i)} - \hat{\mathbf{v}}^{(L)}) = \mathbf{Y}'_i \Delta_i \bmod q$  with  $\Delta_i := s'_i - s_i^{(L)}$ . With probability at least  $1 - L\kappa_{\text{nu}}$  the values  $\Delta_i$  are units in  $\mathcal{R}_q$  for all  $i \in [L]$  (union bound), and by definition of  $\gamma$  we have  $\|\Delta_i\|_{\text{op}} \leq \|s'_i\|_{\text{op}} + \|s_i^{(L)}\|_{\text{op}} \leq 2\gamma$ . This yields, for each  $i$ , a CWSS instance whose slack uses  $2\gamma$ , completing the argument [PS00, BN06, FMN24].

*Proof (of Theorem 3).* 1: *Correctness.* By completeness of  $\Pi_{b, \mathcal{C}}^{\text{ext}}$  and  $\Pi_b^{\text{range}}$ , Step 1 and Step 2 produce valid relations. Further correctness of the following steps follows from the sum-check protocol.

For the norm: since each  $\|\mathbf{v}'_i\|_{\infty} < b$  and each  $\|s_i\|_{\text{op}} \leq \gamma$ ,

$$\left\| \mathbf{v} + \sum_{i \in [L]} s_i \mathbf{v}'_i \right\|_{\infty} \leq \|\mathbf{v}\|_{\infty} + \sum_{i \in [L]} \|s_i\|_{\text{op}} \cdot \|\mathbf{v}'_i\|_{\infty} \leq \beta + Lb\gamma,$$

so the output lies in  $\Xi_{\text{acc}, \beta + Lb\gamma}^{\text{lin}}$ .

2: *Knowledge soundness.* We describe  $\mathcal{E}$  in four stages and account for knowledge error at each stage.

(a) *Folding (coordinate-wise forking).* Rewind in the ROM to obtain  $L + 1$  accepting transcripts for challenges  $\mathbf{s}^{(0)}, \dots, \mathbf{s}^{(L)}$  so that, for each  $i \in [L]$ , the challenge vector differs only in the  $i$ -th coordinate between the  $i$ -th and  $L$ -th transcript, using Lemma 4 with knowledge error  $\kappa_a := L/|\mathcal{D}| + L\kappa_{\text{nu}}$ . Let  $\Delta_i := s_i^{(i)} - s_i^{(L)}$ . We write  $\widehat{\mathbf{v}}^{(i)}$  for the witness in the  $i$ -th transcript.

Since  $\widehat{\Delta}_i \in \mathcal{R}_q^\times$ , we can right-multiply by  $\widehat{\Delta}_i^{-1}$  in  $\mathcal{R}_q$  to obtain a linear instance with the slack absorbed into the witness. Except with probability at most  $\kappa_a := L/|\mathcal{D}| + L\kappa_{\text{nu}}$ , each  $\widehat{\Delta}_i$  is a unit with  $\|\widehat{\Delta}_i\|_{\text{op}} \leq 2\gamma$ , so

$$\left( (\widehat{\mathbf{r}}_i)_{i \in [k]}, \widehat{\mathbf{r}}, \widehat{\mathbf{y}}'_j \right), (\widehat{\mathbf{v}}_i^*, \widehat{\Delta}_i) \right) \in \Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [k]}}^{\text{lin}} \in \Xi_{2\hat{\beta}, 2\gamma}^{\text{lin-slack}},$$

where  $\widehat{\mathbf{v}}_i^* := \widehat{\mathbf{v}}^{(i)} - \widehat{\mathbf{v}}^{(L)}$ . Furthermore, since  $\mathbf{v}^*/\Delta^* := \widehat{\mathbf{v}}^{(L)} - \sum_{i \in [L]} s_i^{(L)} \frac{\widehat{\mathbf{v}}_i^*}{\widehat{\Delta}_i}$  the extractor “reconstructs” the witness for the accumulator

$$\left( (\mathbf{r}_i)_{i \in [k]}, \mathbf{r}, \widetilde{\mathbf{y}} \right), (\mathbf{v}^*, \Delta^*) \right) \in \Xi_{\mathbf{R}, (\widehat{\mathbf{M}}_i)_{i \in [k+1]}}^{\text{lin}} \in \Xi_{\hat{\beta}(2\gamma)^L + L \cdot 2\hat{\beta}(2\gamma)^{L-1}, (2\gamma)^{L-1}}^{\text{lin-slack}}$$

by

$$\mathbf{v}^* := \widehat{\mathbf{v}}^{(L)} \prod_{i \in [L]} \widehat{\Delta}_i + \sum_{i \in [L]} \widehat{\mathbf{v}}_i^* \prod_{j \in [L] \setminus \{i\}} \widehat{\Delta}_j \quad \text{and} \quad \Delta^* := \prod_{i \in [L]} \widehat{\Delta}_i.$$

The norm of  $\mathbf{v}^*$  is bounded by  $\hat{\beta}(2\gamma)^L + L \cdot 2\hat{\beta}(2\gamma)^{L-1}$  denoted further as  $\bar{\beta}$ . The operator norm of  $\Delta^*$  is bounded by  $(2\gamma)^L$  denoted further as  $\delta$ .

(b) *Sum-check.* The extractor runs the prover on random challenges. If the prover rejects, extractor fails. Otherwise, it rewinds the prover (possibly many times) with fresh challenges to obtain (slacked) witnesses  $(\widehat{\mathbf{v}}_i^*, \widehat{s}_i^*)$ ,  $(\widehat{\mathbf{v}}'_i, \widehat{s}'_i)$  for  $i \in [L]$  and  $(\mathbf{v}^*, s^*)$ ,  $(\mathbf{v}', s')$  for the accumulator.

If  $\mathbf{u}^* := \widehat{\mathbf{v}}^*/s^* \neq \mathbf{u}' := \widehat{\mathbf{v}}'/s'$ , then  $\mathbf{R}(\widehat{\mathbf{v}}^* s' - \widehat{\mathbf{v}}' s^*) = \mathbf{0}$  and the extractor outputs a  $\Xi_{\mathbf{R}, 2\bar{\beta}\delta}^{\text{sis}}$ . Similar argument applies if  $\widehat{\mathbf{u}}_i^* := \widehat{\mathbf{v}}_i^*/\widehat{s}_i^* \neq \widehat{\mathbf{u}}'_i := \widehat{\mathbf{v}}'_i/\widehat{s}'_i$ . If  $(\mathbf{u}^*, (\widehat{\mathbf{u}}_i^*)_{i \in [L]})$  form valid witness for the relation specified in Step 4, the extractor outputs

$$\left( (\mathbf{r}''_{i,j})_{i \in [k+1]}, (\mathbf{b}''_{i,j})_{i \in [n+1]}, \mathbf{t}'_j \right), (\widehat{\mathbf{u}}_i^*, \widehat{s}_i^*) \right) \in \Xi_{\bar{\beta}, \delta}^{\text{lin-slack}} \text{ for } j \in [L]$$

Otherwise, as  $(\mathbf{u}^*, (\widehat{\mathbf{u}}_i^*)_{i \in [L]}) = (\mathbf{u}', (\widehat{\mathbf{u}}'_i)_{i \in [L]})$ , we observe that the challenges for the second transcript are independent of the witness in the first, but the sum-check test still passes.

Let  $\ell_0 := \lceil \log \varphi(2 + k + L(2 + n + k)) \rceil$  and  $\ell_1 := \lceil \log(m\varphi \log_{2b} 2B) \rceil$ . By soundness of sum-check and Schwartz-Zippel lemma, probability that the verifier accepts is at most  $\kappa_b := \frac{\ell_0 + \ell_1}{q^e}$ .

(c) *Range.* Apply the extractor of  $\Pi_b^{\text{range}}$  to each  $j \in [L]$ . Either we obtain  $\mathbf{w}_j^*$ :

$$\left( (\mathbf{r}''_{i,j})_{i \in [k+1]}, (\mathbf{b}'_{i,j})_{i \in [n]}, \mathbf{t}'_j \right), \mathbf{w}_j^* \right) \in \Xi_b^{\text{lin}}$$

or we extract a witness in  $\Xi_{\mathbf{R}, 2\bar{\beta}\delta}^{\text{sis}}$ . By the soundness of  $\Pi_b^{\text{range}}$  (Theorem 1), it happens except with probability at most  $\kappa_3 := \frac{L\ell_1(2b+1)}{q^e}$  (via union bound).

For the accumulator, we repeat the “reconstruction” step of (a) to obtain  $\mathbf{w}^* := \mathbf{v}^* - \sum_{i \in [L]} \mathbf{w}_i^*$ , which will be part of the final output, such that

$$\left( (\mathbf{r}_i)_{i \in [k]}, \mathbf{r}, \widetilde{\mathbf{y}} \right), \mathbf{w}^* \right) \in \Xi_{\mathbf{R}, (\widehat{\mathbf{M}}_i)_{i \in [k+1]}}^{\text{lin}} \in \Xi_{\hat{\beta} + Lb\gamma}^{\text{lin}}.$$

| $m\varphi$      | $2^{25}$ | $2^{27}$ | $2^{29}$ |
|-----------------|----------|----------|----------|
| Proof size (KB) | 31.4     | 31.8     | 32.9     |

**Table 1.** Folding proof sizes for different witness dimensions.

(d) *Extension.* From each  $\mathbf{w}_j^*$ , invoke the extractor of  $\Pi_{b,C}^{\text{ext}}$ . Either we recover  $\tilde{\mathbf{w}}_j$ , such that

$$(((\mathbf{r}'_{i,j})_{i \in [k]}, (\mathbf{b}'_{i,j})_{i \in [n]}, \mathbf{y}'_j), \tilde{\mathbf{w}}_j) \in \Xi_{a,n,m,B}^{\text{lin}}$$

or we obtain a witness in  $\Xi_{\mathbf{R}, 2\bar{\beta}\delta}^{\text{sis}}$ . The knowledge error here is  $\kappa_d = L\ell_C/|\mathcal{C}|$ , where  $\ell_C = \lceil \log(a) \rceil$ .

*Conclusion.* By the union bound we obtain the stated knowledge error:

$$\kappa \leq \underbrace{\frac{L/|\mathcal{D}|}{\kappa_a \text{ (unit part)}}}_{\kappa_a \text{ (unit part)}} + \underbrace{\ell_0 + \ell_1/q^e}_{\kappa_b} + \underbrace{L\ell_1(b+1)/q^e}_{\kappa_c} + \underbrace{L\ell_C/|\mathcal{C}|}_{\kappa_d} + \underbrace{L\kappa_{\text{nu}}}_{\text{non-units}}.$$

3: *Communication complexity.* We detail the proof-size contributions (we count prover to verifier messages; verifier challenges  $z, \mathbf{s}$  are ignored as they are derived in the ROM).:

1. **Extension** ( $\Pi_{b,C}^{\text{ext}}$ ): per instance  $j$ , the prover sends  $\mathbf{y}'_j \in \mathcal{R}_q^a$ ; over  $L$  instances this is  $La'$  ring elements.
2. **Range** ( $\Pi_b^{\text{range}}$ ): the ring-side contributes  $L$  ring elements over all  $j$ . The field-side sum-check transcript contributes to  $L(2b+2)\ell$   $\mathbb{F}_{q^e}$  elements in total (with  $\ell = \lceil \log(\log_{2b} 2Bm\varphi) \rceil$ ).
3. **Unification of challenges:** Sum-check (degree 2) contributes  $2 \lceil \log((\log_{2b} 2B)m\varphi) \rceil$   $\mathbb{F}_{q^e}$  elements and then  $(k+2) \cdot (L+1)$   $\mathcal{R}_{q^e}$  elements for the claims over  $\mathcal{R}_{q^e}$ .

Summing ring contributions gives  $La' + L$  over  $\mathcal{R}_q$ ,  $(k+2) \cdot (L+1)$  over  $\mathcal{R}_{q^e}$ ,  $2 \lceil \log m\varphi(\log_{2b} 2B) \rceil$   $\mathbb{F}_{q^e}$  elements and  $L(2b+2) \lceil \log(m\varphi(\log_{2b} 2B)) \rceil$   $\mathbb{F}_{q^e}$  elements.

4: *Extractor running time.* The extractor runs in expected time polynomial due to concatenation of expected polynomial-time extractors.

*Remark 2.* We remark that sum-checks from Steps 1 and 2 could be merged into 2 sum-checks (instead of over  $L$  instances), further reducing the communication complexity from  $Lb \lceil \log(m\varphi(\log_{2b} 2B)) \rceil$   $\mathbb{F}_{q^e}$  elements to  $b \lceil \log(m\varphi(\log_{2b} 2B)) \rceil$   $\mathbb{F}_{q^e}$  elements with a negligible impact on the knowledge error.

## 6.1 Parameters Selection and Efficiency Estimates

We set the parameters for the folding scheme  $\Pi_{b,D,C}^{\text{fs}}$  to optimise communication complexity and prover time. For simplicity, we consider  $L = 1$ , i.e., folding a single instance of  $\Xi_{a,n,m,B}^{\text{lin}}$  into an accumulator  $\Xi_{\text{acc}, \hat{\beta}}^{\text{lin}}$ . We set  $n = 3$  and  $k = 1$  to match the R1CS reduction setting. We bound the number of rounds to  $2^6$  and set the relation norm to  $B = 2^{10}$ . The degree of the cyclotomic ring is  $\varphi = 128$  (almost matching [BC25b]). We use  $q \approx 2^{50}$ , motivated by efficient vectorized arithmetic in  $\mathcal{R}_q$ . We consider  $m\varphi \in \{2^{25}, 2^{27}, 2^{29}\}$ , where the middle setting is close to [BC25b]. Proof sizes are summarised in Table 1, detailed in Section C.

*Remark 3 (Efficiency Estimates).* Repeating the setting of Theorem 3 and applying Remark 2 we summarise the following complexity estimates:

- **Prover time:** Dominated by  $O(La'm \log_{2b} 2B)$   $\mathcal{R}_q$ -multiplications.

- **Verifier time (excluding hashing):** Dominated by  $O(La')$   $\mathcal{R}_q$ -multiplications.
- **Online instance size:**  $L \cdot (a' + k + n)$   $\mathcal{R}_q$ -elements.
- **Accumulated instance size:**  $(a' + k + 1)$   $\mathcal{R}_q$ -elements.
- **Folding proof size:**  $La' + L$  elements in  $\mathcal{R}_q$ ,  $(k + 2) \cdot (L + 1)$  elements in  $\mathcal{R}_{q^e}$ ,  $2 \lceil \log(m\varphi(\log_{2b} 2B)) \rceil$   $\mathbb{F}_{q^e}$ , and  $(2b + 2) \lceil \log(m\varphi(\log_{2b} 2B)) \rceil$   $\mathbb{F}_{q^e}$  elements.

**Comparison with [BC25b]** All metrics from Remark 3 are favorable to our solution compared with [BC25b], except for prover time, where the comparison is less direct because [BC25b] reports prover runtime by separating  $\mathcal{R}_q$  additions and  $\mathcal{R}_q$  multiplications (dominated by  $Lna$   $\mathcal{R}_q$  multiplications and  $O(Lma\varphi \log_\varphi B)$   $\mathcal{R}_q$  additions, adapting the notation). To argue that our prover runtime is strictly better, we explicitly measure runtimes of  $\mathcal{R}_q$  arithmetic operations for the extension commitment and related operations (not a full pipeline). After unifying settings and parameters, we estimate that in a parameter regime similar to that in [BC25b], our prover time, excluding the impact of sum-check, is about  $3.5\times$  faster, at approximately 36.6 s (compared to 129.4 s in [BC25b]). The instance considered in [BC25b] is relatively large, and those benchmarks do not account for parallelism. Parameter selection, efficiency estimates, and memory estimates are deferred to Section C.

# 7 R1CS/CCS over $\mathbb{F}_q$ to the principal linear relation

Often, one is interested in applying folding schemes on non-linear constraints expressed over a finite field  $\mathbb{F}_q$ , as for example the R1CS or CCS constraint over  $\mathbb{F}_q$ . In this section we explain how to encode such a constraint as a (non-linear) constraint over  $\mathcal{R}_q$ , and then we provide a reduction of knowledge from this to our principal linear relation in a way that most of the computation occurs over  $\mathbb{F}_q$ , rather than over  $\mathcal{R}_q$ . Our methods are ultimately equivalent to those of Neo [NS25], but we believe our formulation is much simpler algebraically and is of independent interest.

## 7.1 A low-norm, bit-size preserving encoding of $\mathbb{F}_q$ in $\mathcal{R}_q$ via module homomorphic preimages

We proceed to present an encoding of field elements as ring elements. As we mentioned, this is equivalent to Neo’s encoding, but we use an alternative point of view via module homomorphisms. Fix a prime  $q$  and a cyclotomic polynomial  $\Phi_f(X)$ . As usual, we represent elements from  $\mathcal{R}_q = \mathbb{F}_q[X]/\langle \Phi_f(X) \rangle$  as polynomials of degree less than  $\varphi = \deg(\Phi_f(X))$  and with coefficients in  $\mathbb{F}_q$ . Throughout this section, we sometimes look at  $\mathcal{R}_q$  as a  $\mathbb{F}_q$ -module consisting of all polynomials of degree less than  $\deg(\Phi_f(X))$  with coefficients in  $\mathbb{F}_q$ , equipped with the natural addition operation and  $\mathbb{F}_q$ -scalar multiplication. Given a positive integer  $k$ , we define the map:

$$\theta_k : \mathcal{R}_q \rightarrow \mathbb{F}_q \text{ by } f(X) \mapsto f(k) \pmod{q} \quad (7)$$

**Lemma 5.** *The map  $\theta_k$  is a well-defined  $\mathbb{F}_q$ -module homomorphism.*

*Proof.*  $\theta_k$  is well defined when  $\mathcal{R}_q$  is understood as the module described above (i.e., the value  $\theta_k(f(X))$  is independent of module equivalence class representatives<sup>9</sup>). Additionally,  $\theta_k(f(X) +$

<sup>9</sup> Note that as soon as we look at  $\mathcal{R}_q$  as a ring, then  $\theta_k$  is not necessarily well defined:  $\theta_k(f(X))$  is not invariant under changing equivalence class representatives.

$g(X)) = (f(k) + g(k)) \bmod q = (f(k) \bmod q) + (g(k) \bmod q) = \theta_k(f(X)) + \theta_k(g(X))$  for all  $f(X), g(X) \in \mathcal{R}_q$ ;  $\theta_k(af(X)) = af(k) \bmod q = a\theta_k(f(X))$  for all  $f(X) \in \mathcal{R}_q, a \in \mathbb{F}_q$ ; and  $\theta_k(0) = 0$ .

*Remark 4.* One can prove that if  $q = \Phi_f(k)$ , then  $\theta_k : \mathcal{R}_q \rightarrow \mathbb{F}_q$  is a well-defined surjective ring homomorphism with kernel the ideal generated by  $X - k$ . This is however not relevant for our work.

Let  $\ell_k(q) = \lfloor \log_k(q) \rfloor$ , and assume  $\ell_k(q) < \varphi$ . For each  $c \in \mathbb{F}_q$ , let  $c_0, \dots, c_{\ell_k(q)} \in [0, k-1]$  be such that  $c = c_0 + c_1 \cdot k + \dots + c_{\ell_k(q)} \cdot k^{\ell_k(q)}$ . Note that  $\ell_k(q)$  is either  $\deg(\Phi_f(X)) - 1$  or  $\deg(\Phi_f(X))$ , depending on whether  $q = \Phi_f(k) < k^\varphi$  or  $q > k^\varphi$ , respectively. For each  $c \in \mathbb{F}_q$  we define the following element from  $\mathcal{R}_q$ :

$$p_c(X) = c_0 + c_1 \cdot X + \dots + c_{\ell_k(q)} \cdot X^{\ell_k(q)}. \quad (8)$$

*Remark 5.* Let  $c \in \mathbb{F}_q$  and let  $p_c(X)$  be defined as above. Then the base- $k$  representation of  $c$  is the same as  $\mathbf{cf}(p_c(X))$ .

We show that  $\theta_k$  is well-behaved w.r.t. the MLEs of vectors of ring elements.

**Lemma 6.** *Let  $\mathbf{v} \in \mathcal{R}_q^m$  be a vector of ring elements. Consider the MLEs  $\text{MLE}[\mathbf{v}]$  and  $\text{MLE}[\theta_k(\mathbf{v})]$  of  $\mathbf{v}$  and  $\theta_k(\mathbf{v})$ , respectively, which are multilinear polynomials with coefficients in  $\mathcal{R}_q$  and in  $\mathbb{F}_q$ , respectively. Then, for all  $\mathbf{x} \in \mathbb{F}_q^{\log m}$ ,*

$$\theta_k(\text{MLE}[\mathbf{v}](\mathbf{x})) = \text{MLE}[\theta_k(\mathbf{v})](\mathbf{x}).$$

*Proof.* Since  $\theta_k$  is an  $\mathbb{F}_q$ -module homomorphism,

$$\begin{aligned} \theta_k(\text{MLE}[\mathbf{v}](\mathbf{x})) &= \theta_k \left( \sum_{\mathbf{b} \in \{0,1\}^{\log m}} \mathbf{eq}(\mathbf{b}, \mathbf{x}) \mathbf{v}_{\mathbf{b}} \right) \\ &= \sum_{\mathbf{b} \in \{0,1\}^{\log m}} \mathbf{eq}(\mathbf{b}, \mathbf{x}) \theta_k(\mathbf{v}_{\mathbf{b}}) = \text{MLE}[\theta_k(\mathbf{v})](\mathbf{x}), \end{aligned}$$

where we have used that  $\mathbf{eq}(\mathbf{b}, \mathbf{x}) \in \mathbb{F}_q$  for all  $\mathbf{b} \in \{0,1\}^{\log m}$ .

Given a field extension  $\mathbb{F}_{q^\varphi}$  of  $\mathbb{F}_q$ , and the corresponding ring  $\mathcal{R}_{q^\varphi} = \mathbb{F}_{q^\varphi}[X]/\langle \Phi_f(X) \rangle$ , the map  $\theta_k$  can be extended to a  $\mathbb{F}_{q^\varphi}$ -module homomorphism  $\theta_k : \mathcal{R}_{q^\varphi} \rightarrow \mathbb{F}_{q^\varphi}$  that sends each  $f(X) \in \mathcal{R}_{q^\varphi}$  to  $f(k) \bmod q^\varphi$  (where we see  $\mathcal{R}_{q^\varphi}$  as the module formed by polynomials of degree less than  $\deg(\Phi_f)$ , with coefficients in  $\mathbb{F}_{q^\varphi}$ ).

## 7.2 Reduction to the committed hybrid R1CS relation

We next rewrite R1CS relations over  $\mathbb{F}_q$  as what we call *committed hybrid R1CS relations*. In a nutshell, these are R1CS relations over  $\mathbb{F}_q$  where a  $\theta_k$ -preimage of the witness has been committed over  $\mathcal{R}_q$  using Ajtai's commitment. Analogous ideas can be used for CCS relations [NS25] over  $\mathbb{F}_q$ . We omit these for brevity.

Let  $\mathbb{F}_q$  be a finite prime field with  $q$  elements. Let  $a, m, \ell$  be size parameters, with  $m \geq \ell + 1$  and  $m$  being a power of two, and let  $(\mathbf{M}_i)_{i \in [3]}$  be three matrices from  $\mathcal{R}^{m \times m}$ . The *R1CS relation over  $\mathbb{F}_q$*  is defined as:

$$\Xi_{\mathbb{F}_q, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B}^{\text{R1CS}} := \left\{ \begin{array}{l} \mathbf{x}, \mathbf{w} : \\ \mathbf{x} \in \mathbb{F}_q^\ell, \mathbf{w} \in \mathbb{F}_q^{m-\ell-1}, \mathbf{M}_i \in \mathbb{F}_q^{m \times m} \text{ for all } i \in [3], \\ (\mathbf{M}_0 \cdot \mathbf{z}) \circ (\mathbf{M}_1 \cdot \mathbf{z}) = \mathbf{M}_2 \cdot \mathbf{z} \quad \text{and} \quad \mathbf{z} = (\mathbf{x}, 1, \mathbf{w}) \in \mathbb{F}_q^m \end{array} \right\}.$$

Let  $\mathcal{R}_q$  be a cyclotomic ring. Let  $\theta_k : \mathcal{R}_q \rightarrow \mathbb{F}_q$  be the  $\mathbb{F}_q$ -module homomorphism from Eq. (7), with base  $k$ , so that  $\theta_k(f(X)) = f(k)$  for all  $f(X) \in \mathcal{R}_q$ . The *committed hybrid R1CS relation over  $(\mathcal{R}_q, \mathbb{F}_q)$*  is defined as follows. We highlight in blue the only difference from the previous relation.

$$\Xi_{\mathcal{R}_q, \theta_k, \mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B}^{\text{com-hyb-R1CS}} := \left\{ \begin{array}{l} (\mathbf{x}, \mathbf{y}), \mathbf{w} : \\ \mathbf{x} \in \mathcal{R}_q^\ell, \mathbf{y} \in \mathcal{R}_q^a, \mathbf{w} \in \mathcal{R}_q^{m-\ell-1}, \\ \mathbf{M}_i \in \mathbb{F}_q^{m \times m} \text{ for all } i \in [3], \mathbf{A} \in \mathcal{R}_q^{a \times m}, \\ (\mathbf{M}_0 \cdot \theta_k(\mathbf{z})) \circ (\mathbf{M}_1 \cdot \theta_k(\mathbf{z})) - \mathbf{M}_2 \cdot \theta_k(\mathbf{z}) = 0, \\ \mathbf{z} = (\mathbf{x}, 1, \mathbf{w}) \in \mathcal{R}_q^m, \mathbf{A}\mathbf{z} = \mathbf{y}, \|\mathbf{z}\|_\infty \leq k \end{array} \right\}.$$

*Remark 6.* The above definitions generalize in a straightforward way to the concept of *committed hybrid CCS relations over  $(\mathcal{R}_q, \mathbb{F}_q)$* .

**Theorem 4.** Let  $\text{pp} = (\mathbb{F}_q, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B)$  be parameters for an R1CS relation over  $\mathbb{F}_q$ . Let  $\mathcal{R}_q$  be the cyclotomic polynomial defined by  $q$  and  $\Phi_f(X)$ . Let  $\text{pp}' = (\mathcal{R}_q, \theta_q, \mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B)$  be parameters for a committed hybrid R1CS relation over  $(\mathcal{R}_q, \mathbb{F}_q)$ . Assume  $\mathbf{A}, a, B$  are chosen so that MSIS is sufficiently hard (cf. Section 3). Assume further that  $2k < B$ .

Then, for every  $(\mathbf{x}, \mathbf{w}) \in \mathbb{F}_q^\ell \times \mathbb{F}_q^{m-\ell-1}$  for  $\Xi_{\text{pp}}^{\text{R1CS}}$  there is an instance-witness pair  $((\mathbf{x}', \mathbf{y}), \mathbf{w}') \in \mathcal{R}_q^\ell \times \mathcal{R}_q^a \times \mathcal{R}_q^{m-\ell-1}$  for  $\Xi_{\text{pp}'}^{\text{com-hyb-R1CS}}$  such that:

1.  $(\mathbf{x}, \mathbf{w}) \in \Xi_{\text{pp}}^{\text{R1CS}}$  if and only if  $((\mathbf{x}', \mathbf{y}), \mathbf{w}') \in \Xi_{\text{pp}'}^{\text{com-hyb-R1CS}}$ .
2. Let  $w_i$  and  $w'_i$  be the  $i$ -th entry of  $\mathbf{w}$  and  $\mathbf{w}'$ , for each  $i \in [m - \ell - 1]$ . Then the base- $k$  representation of  $w_i$  is the same as  $\text{cf}(w'_i)$ , for all  $i \in [m - \ell - 1]$ . An analogous statement holds for the entries of  $\mathbf{x}$  and  $\mathbf{x}'$ .

*Proof.* First we construct  $\mathbf{x}', \mathbf{y}$  and  $\mathbf{w}'$ , and afterward we prove the required properties. Write  $\mathbf{x} = (x_0, \dots, x_{\ell-1})$  and  $\mathbf{w} = (w_0, \dots, w_{m-\ell-2})$ . Define  $\mathbf{x}' = (p_{x_0}(X), \dots, p_{x_{\ell-1}}(X)) \in \mathcal{R}_q^\ell$  and  $\mathbf{w}' = (p_{w_0}(X), \dots, p_{w_{m-\ell-2}}(X)) \in \mathcal{R}_q^{m-\ell-1}$ , where  $p_{x_i}(X), p_{w_i}(X)$  are defined as in Eq. (8). Then  $\theta_k(\mathbf{x}') = \mathbf{x}$  and  $\theta_k(\mathbf{w}') = \mathbf{w}$ . Let  $\mathbf{z} = (\mathbf{x}, 1, \mathbf{w})$  and  $\mathbf{z}' = (\mathbf{x}', 1, \mathbf{w}')$ . Then  $\theta_k(\mathbf{z}') = \theta_k(\mathbf{x}', 1, \mathbf{w}') = (\mathbf{x}, 1, \mathbf{w}) = \mathbf{z}$ . Hence  $(\mathbf{M}_0 \mathbf{z}) \circ (\mathbf{M}_1 \mathbf{z}) - \mathbf{M}_2 \mathbf{z} = 0$  if and only if  $(\mathbf{M}_0 \theta_k(\mathbf{z}')) \circ (\mathbf{M}_1 \theta_k(\mathbf{z}')) - \mathbf{M}_2 \theta_k(\mathbf{z}') = 0$ . Further, by construction, all the elements  $p_{x_i}$  and  $p_{w_i}$  have coefficients in the range  $[0, k-1]$  and so  $\text{cf}(\mathbf{z}') \subseteq [0, k-1]^{m\varphi}$ . Thus the instance-witness pair  $((\mathbf{x}', \mathbf{y}), \mathbf{w}')$  for  $\Xi_{\text{pp}'}^{\text{com-hyb-R1CS}}$ , where  $\mathbf{y} = \mathbf{A}\mathbf{z}'$ , satisfies all constraints in the definition of  $\Xi_{\text{pp}'}^{\text{com-hyb-R1CS}}$ . This completes the proof of Item 1. Item 2 follows from the definition of  $\mathbf{w}'$  and Remark 5.

Theorem 4 allows us to proceed as follows. Suppose a prover wants to prove knowledge of a valid witness  $\mathbf{w}$  for an R1CS instance (or CCS instance)  $\mathbf{x}$  over a field  $\mathbb{F}_q$ . Then the prover may as well prove knowledge of a valid witness  $\mathbf{w}'$  for the instance  $(\mathbf{x}', \mathbf{y})$  given by Theorem 4, for a committed hybrid R1CS relation over  $\mathcal{R}_q$  (or analogous committed hybrid CCS relation).

The definitions and results presented in this section extend in a standard and straightforward way to CCS relations [STW23].

## 7.3 Reduction to the principal linear relation

We next describe a reduction of knowledge from the committed hybrid R1CS relation to our principal linear relation. Similarly as achieved in Neo [NS25], this reduction makes use of the module homomorphism  $\theta_k$  to avoid performing costly sum-checks over  $\mathcal{R}_q$ , staying over  $\mathbb{F}_q$  instead. Again, the techniques we present extend in a straightforward way to CCS constraints.

## From committed hybrid R1CS to the principal linear relation

$$\Pi^{\text{hyb-R1CS}} : \left( (\mathbf{x} \in \mathcal{R}_q^\ell, \mathbf{y} \in \mathcal{R}_q^a, \mathbf{w} \in \mathcal{R}_q^{m-\ell-1}) \in \Xi_{\mathcal{R}_q, \theta_k, \mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B}^{\text{com-hyb-R1CS}} \right) \rightarrow \left( (\mathbf{r}' \in \mathcal{R}_{q^e}^{\log(m)^3}, \mathbf{b}' \in \mathcal{R}_{q^e}^{\log m}), \mathbf{y}' \in \mathcal{R}_q^a \times \mathcal{R}_{q^e}^4, \mathbf{w}' \in \mathcal{R}_q^m \right) \in \Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, 1, m, B}^{\text{lin}}$$

1. Verifier samples a random vector  $\mathbf{r} \in \mathbb{F}_{q^e}^{\log m}$  and sends  $\mathbf{r}$  to the prover.
2. Define  $\mathbf{w}' = (\mathbf{x}, 1, \mathbf{w}) \in \mathcal{R}_q^m$ , let  $\theta_k(\mathbf{w}') \in \mathbb{F}_q^m$  be the result of applying  $\theta_k$  to  $\mathbf{w}'$  component-wise, and let  $Q(\mathbf{Y})$  be the polynomial on variables  $\mathbf{Y} = (Y_0, \dots, Y_{\log m-1})$  and coefficients in  $\mathbb{F}_q$  defined as

$$Q(\mathbf{Y}) = Q_0(\mathbf{Y})Q_1(\mathbf{Y}) - Q_2(\mathbf{Y})$$

$$Q_i(\mathbf{Y}) = \sum_{\mathbf{b}' \in \{0,1\}^{\log m}} \text{MLE}[\mathbf{M}_i](\mathbf{Y}, \mathbf{b}') \text{MLE}[\theta_k(\mathbf{w}')](\mathbf{b}') \quad \text{for } i \in [3].$$

3. Prover and verifier engage in the sum-check protocol over  $\mathbb{F}_{q^e}$  and reduce

$$\sum_{\mathbf{b} \in \{0,1\}^{\log m}} Q(\mathbf{b}) \text{eq}(\mathbf{b}; \mathbf{r}) \stackrel{?}{=} 0 \longrightarrow Q(\mathbf{u}) \text{eq}(\mathbf{u}, \mathbf{r}) \stackrel{?}{=} c,$$

where  $\mathbf{u} \in \mathbb{F}_{q^e}^{\log m}$  is the vector of challenges sampled by the verifier, and  $c \in \mathbb{F}_{q^e}$  is certain field element determined during the execution of the sum-check protocol.

4. Prover computes the ring elements  $d_i = \sum_{\mathbf{b}' \in \{0,1\}^{\log m}} \text{MLE}[\mathbf{M}_i](\mathbf{u}, \mathbf{b}') \text{MLE}[\mathbf{w}'](\mathbf{b}') \in \mathcal{R}_{q^e}$  for  $i \in [3]$ , and sends these to the verifier.
5. Verifier asserts  $(\theta_k(d_0)\theta_k(d_1) - \theta_k(d_2))\text{eq}(\mathbf{u}; \mathbf{r}) \stackrel{?}{=} c$ .
6. Verifier samples  $\mathbf{v} \in \mathcal{C}^{\log(\ell)+1}$  and sends  $\mathbf{v}$  to prover. This will be used as an evaluation point to guarantee that the output witness  $\mathbf{w}'$  starts with the public input  $(\mathbf{x}, 1)$ .
7. Prover and verifier compute the ring element  $e = \text{MLE}[(\mathbf{x}, 1)](\mathbf{v}) \in \mathcal{R}_{q^e}$ , and output  $((\mathbf{r}'_i)_{i \in [3]}, \mathbf{b}', \mathbf{y}'), \mathbf{w}'$ , where:

$$\begin{aligned} \mathbf{r}' &= (\mathbf{u}, \mathbf{u}, \mathbf{u}) \in \mathcal{R}_{q^e}^{3 \times \log(m)} & \mathbf{b}' &= (\mathbf{v}, \mathbf{0}) \in \mathcal{R}_{q^e}^{\log m} \\ \mathbf{y}' &= (\mathbf{y}, d_0, d_1, d_2, e) \in \mathcal{R}_q^a \times \mathcal{R}_{q^e}^4 & \mathbf{w}' &= (\mathbf{x}, 1, \mathbf{w}) \in \mathcal{R}_q^m \end{aligned}$$

Fig. 4. Reduction from committed hybrid R1CS to the principal linear relation.

Here we choose to treat the public part  $(\mathbf{x}, 1)$  of the R1CS instance-witness pair in a slightly different way than in prior folding schemes. Namely, instead of carrying it over to the principal linear relation, we remove it altogether, so that the principal linear relation only uses vectors of witness elements  $\mathbf{w}'$  (instead of vectors where a public instance is concatenated with a witness). To do so, in our reduction to the linear relation (Fig. 4), we add an MLE evaluation for  $\mathbf{w}'$  that guarantees that  $\mathbf{w}'$  starts with  $(\mathbf{x}, 1)$ , except with negligible probability. See Steps 6 and 7 in Fig. 4 and the proof of Theorem 5.

Let  $\text{pp} = (\mathcal{R}_q, \theta_k, \mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B)$  be parameters for the committed hybrid R1CS relation. Let  $\mathbb{F}_{q^e}$  be a field extension of  $\mathbb{F}_q$  of degree  $z$ , and let  $\mathcal{R}_{q^e} = \mathbb{F}_{q^e}[X]/\langle \Phi_f(X) \rangle$ . In Fig. 4 we describe a reduction of knowledge from  $\Xi_{\text{pp}}^{\text{com-hyb-R1CS}}$  to  $\Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, 1, m, B}^{\text{lin}}$ . The reduction follows the same blueprint as Hypernova's [KS24] and LatticeFold's [BC25a] linearization steps.

**Theorem 5.** *Let  $q$  be a prime,  $\mathcal{R}$  be a cyclotomic ring with a conductor  $f$ ,  $B, m, a, \ell, k \in \mathbb{N}$ ,  $\mathbf{A} \in \mathcal{R}_q^{a \times m}$ ,  $(\mathbf{M}_i \in \mathbb{F}_q^{m \times m})_{i \in [3]}$ ,  $\varphi := \varphi(f)$ . Let  $\theta_k$  be a map defined as in Eq. (7). Let  $\mathcal{C}$  be a strong sampling set.  $\Pi^{\text{hyb-R1CS}}$  is a reduction of knowledge. It is perfectly correct for*

$$\Xi_{\mathcal{R}_q, \ker \theta, \mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B}^{\text{com-hyb-R1CS}} \rightarrow \Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, n, m, B}^{\text{lin}}$$

It is knowledge sound with knowledge error  $\kappa = \log(\ell) + 1/|C| + 4\log(m)/q^e$

$$(\Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, n, m, B'}^{\text{lin}} \cup \Xi_{\mathbf{A}, a, m, 2B'}^{\text{sis}}) \leftarrow \Xi_{\mathcal{R}_q, \ker \theta, \mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, m, \ell, B'}^{\text{com-hyb-R1CS}}$$

The communication cost is  $3\log(m)$   $\mathbb{F}_{q^e}$  elements and  $3\mathcal{R}_q$  elements.

*Proof. Correctness:* We show that the output  $((\mathbf{r}'_i)_{i \in [3]}, \mathbf{b}', \mathbf{y}'), \mathbf{w}'$  satisfies

$$\begin{pmatrix} \mathbf{A} \\ \text{tensor}(\mathbf{r}'_0)^T \mathbf{M}_0 \\ \text{tensor}(\mathbf{r}'_1)^T \mathbf{M}_1 \\ \text{tensor}(\mathbf{r}'_2)^T \mathbf{M}_2 \\ \text{tensor}(\mathbf{b}')^T \end{pmatrix} \mathbf{w}' = \mathbf{y}'$$

and  $\text{cf}(\mathbf{w}') \in [0, B)^{\varphi m}$ . For the matrix condition, we argue block-by-block. The first block, i.e.,  $\mathbf{A}\mathbf{w}' = \mathbf{y}$  comes from the definition of the input relation. Then, for  $i \in [3]$ , we have  $\text{tensor}(\mathbf{r}'_i)^T \mathbf{M}_i \mathbf{w}' = d_i$ , which holds immediately as  $\mathbf{r}_i = \mathbf{u}$  and

$$d_i = \sum_{\mathbf{b}' \in \{0,1\}^{\log m}} \text{MLE}[\mathbf{M}_i](\mathbf{u}, \mathbf{b}') \text{MLE}[\mathbf{w}'](\mathbf{b}') = \text{tensor}(\mathbf{u})^T \mathbf{M}_i \mathbf{w}'$$

Eventually, the equality  $\text{tensor}(\mathbf{b}')^T \mathbf{w}' = e$  holds, because

$$\begin{aligned} \text{tensor}(\mathbf{b}')^T \mathbf{w}' &= \text{tensor}((\mathbf{v}, \mathbf{0}))^T (\mathbf{x}, 1, \mathbf{w}) \\ &= \text{MLE}[(\mathbf{x}, 1, \mathbf{w})](\mathbf{v}, \mathbf{0}) = \text{MLE}[(\mathbf{x}, 1)](\mathbf{v}) = e. \end{aligned}$$

The norm bound is directly inherited from the input relation.

*Knowledge soundness:* The extractor, given a prover  $\mathcal{P}^*$  which succeeds with probability  $\epsilon$ , runs  $\mathcal{P}^*$ . If the execution fails, the extractor aborts. If the execution succeeds,  $\mathcal{P}^*$  outputs

$$(\mathbf{r}_0^*, \mathbf{r}_1^*, \mathbf{r}_2^*, \mathbf{b}^*, (\hat{\mathbf{y}}^*, d_0^*, d_1^*, d_2^*, e^*), (\mathbf{x}^*, u^*, \mathbf{w}^*)) \in \Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, 1, m, B'}^{\text{lin}}.$$

The extractor then runs  $\mathcal{P}^*$  as many times as it needs to get another accepting transcript, which we parse as

$$(\mathbf{r}'_0, \mathbf{r}'_1, \mathbf{r}'_2, \mathbf{b}', (\hat{\mathbf{y}}', d'_0, d'_1, d'_2, e'), (\mathbf{x}', u', \mathbf{w}')) \in \Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [3]}, a, 1, m, B'}^{\text{lin}}.$$

Suppose that  $\mathbf{w}^* \neq \mathbf{w}'$ . Then the extractor outputs  $\mathbf{w}^* - \mathbf{w}' \in \Xi_{\mathbf{A}, a, m, 2B'}^{\text{sis}}$ . Assume now that  $\mathbf{w}^* = \mathbf{w}'$ . Define  $\mathbf{z}^* = \theta_k((\mathbf{x}^*, u^*, \mathbf{w}^*))$ . We argue that the equalities  $\mathbf{x}^* = \mathbf{x}$ ,  $u^* = 1$  and  $(\mathbf{M}_0 \mathbf{z}^*) \circ (\mathbf{M}_1 \mathbf{z}^*) = \mathbf{M}_2 \mathbf{z}^*$  hold with high probability.

The equalities  $\mathbf{x}^* = \mathbf{x}$  and  $u^* = 1$  come from the Schwartz-Zippel lemma applied to the condition  $\text{tensor}(\mathbf{b}')^T \mathbf{w}^* = e^*$  and have an error probability of  $\log(\ell) + 1/|C|$ . Applying  $\theta_k$  and Lemma 6 to the equality

$$\text{tensor}(\mathbf{r}'_i)^T \mathbf{M}_i \mathbf{w}' = d'_i,$$

we have:

$$\sum_{\mathbf{b} \in \{0,1\}^{\log m}} \text{MLE}[\mathbf{M}_i](\mathbf{u}', \mathbf{b}) \text{MLE}[\theta_k(\mathbf{w}')](\mathbf{b}) = \theta_k(d'_i).$$

Due to the verification, we have:  $(\theta_k(d'_0)\theta_k(d'_1) - \theta_k(d'_2))\text{eq}(\mathbf{u}; \mathbf{r}') = c$  and so we obtain that  $Q(\mathbf{u}')\text{eq}(\mathbf{u}'; \mathbf{r}') = c$ . From the soundness of sum-check, we conclude:  $\sum_{\mathbf{b} \in \{0,1\}^{\log(m)}} Q(\mathbf{b})\text{eq}(\mathbf{b}; \mathbf{r}') = 0$

expect with error probability  $2^{\log(m)}/q^\epsilon$ . Using Schwartz-Zippel lemma on the polynomial  $Q(\mathbf{Y})$  of total degree at most  $2\log(m)$ , we get (by Lemma 3)  $Q(\mathbf{Y}) = 0$  except with probability  $2^{\log(m)}/q^\epsilon$ . Translating  $Q(\mathbf{Y}) = 0$  from multilinear extension to matrices yields the desired condition. Accounting for all knowledge errors via union bound gives us a knowledge error of  $\kappa := \log(\ell) + 1/|C| + 4\log(m)/q^\epsilon$ .

*Extractor runtime:* First, the extractor runs a polynomial-time algorithm  $\mathcal{P}^*$  once. If the execution succeeds, the extractor runs  $\mathcal{P}^*$  again an expected number of times equal to  $1/\epsilon$ . In total, the expected runtime of the extractor is  $\frac{1}{\epsilon}(\epsilon + 1) = 1 + \epsilon$  times some polynomial. In conclusion, the extractor runs in expected polynomial time.

*Communication costs:* In each round of the sum-check, 3 field elements are sent and there are  $\log(m)$  rounds. The prover also sends 3 ring elements. In total, the prover sends  $3\log(m)$  field elements and 3 ring elements.

**Acknowledgments.** Lipmaa and Luhaäär were co-funded by the European Union and the Estonian Research Council through the project TEM-TA119 and by the Estonian Research Council grant PRG2531. The work of Osadnik was supported by the Research Council of Finland project No. 358951.

# References

- ACGS24. Diego F. Aranha, Anamaria Costache, Antonio Guimarães, and Eduardo Soria-Vazquez. HELIOPOLIS: Verifiable computation over homomorphically encrypted data from interactive oracle proofs is practical. In Kai-Min Chung and Yu Sasaki, editors, *ASIACRYPT 2024, Part V*, volume 15488 of *LNCS*, pages 302–334. Springer, Singapore, December 2024. doi:10.1007/978-981-96-0935-2\_10. 1
- ACK21. Thomas Attema, Ronald Cramer, and Lisa Kohl. A compressed  $\Sigma$ -protocol theory for lattices. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part II*, volume 12826 of *LNCS*, pages 549–579, Virtual Event, August 2021. Springer, Cham. doi:10.1007/978-3-030-84245-1\_19. 1
- ACX19. Thomas Attema, Ronald Cramer, and Chaoping Xing. A note on short invertible ring elements and applications to cyclotomic and trinomials number fields. *Cryptology ePrint Archive*, Report 2019/1200, 2019. URL: <https://eprint.iacr.org/2019/1200>. 4, 1.1
- Ajt96. Miklós Ajtai. Generating hard instances of lattice problems (extended abstract). In *28th ACM STOC*, pages 99–108. ACM Press, May 1996. doi:10.1145/237814.237838. 1
- ALS20. Thomas Attema, Vadim Lyubashevsky, and Gregor Seiler. Practical product proofs for lattice commitments. In Daniele Micciancio and Thomas Ristenpart, editors, *CRYPTO 2020, Part II*, volume 12171 of *LNCS*, pages 470–499. Springer, Cham, August 2020. doi:10.1007/978-3-030-56880-1\_17. 8, B.2
- APS15. Martin R. Albrecht, Rachel Player, and Sam Scott. On the concrete hardness of learning with errors. *Cryptology ePrint Archive*, Report 2015/046, 2015. URL: <https://eprint.iacr.org/2015/046>. C.1, C.1
- BC25a. Dan Boneh and Binyi Chen. LatticeFold: A lattice-based folding scheme and its applications to succinct proof systems. In Goichiro Hanaoka and Bo-Yin Yang, editors, *ASIACRYPT 2025, Part III*, volume 16247 of *LNCS*, pages 330–362. Springer, Singapore, December 2025. doi:10.1007/978-981-95-5099-9\_11. 1, 2.1, 2.1, 2.3, 7.3, C.4
- BC25b. Dan Boneh and Binyi Chen. LatticeFold+: Faster, simpler, shorter lattice-based folding for succinct proof systems. In Yael Tauman Kalai and Seny F. Kamara, editors, *CRYPTO 2025, Part VII*, volume 16006 of *LNCS*, pages 327–361. Springer, Cham, August 2025. doi:10.1007/978-3-032-01907-3\_11. 1, 1, 1.1, 2.1, 2.1, 2.2, 2.3, 2.5, 2.7, 6.1, 6.1, C, C.1, 2, C.2, C.2, C.3, C.3, C.4, 4
- BCCT12. Nir Bitansky, Ran Canetti, Alessandro Chiesa, and Eran Tromer. Recursive composition and bootstrapping for SNARKs and proof-carrying data. *Cryptology ePrint Archive*, Report 2012/095, 2012. URL: <https://eprint.iacr.org/2012/095>. 1
- BCFW25. Benedikt Bünz, Alessandro Chiesa, Giacomo Fenzi, and William Wang. Linear-Time Accumulation Schemes. In Benny Applebaum and Rachel Lin, editors, *TCC 2025 (1)*, volume 16268, pages 369–399, Aarhus, Denmark, December 1–5, 2025. Springer, Cham. doi:10.1007/978-3-032-12287-2\_13. 1

- BCL<sup>+</sup>21. Benedikt Bünz, Alessandro Chiesa, William Lin, Pratyush Mishra, and Nicholas Spooner. Proof-carrying data without succinct arguments. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part I*, volume 12825 of *LNCS*, pages 681–710, Virtual Event, August 2021. Springer, Cham. doi: 10.1007/978-3-030-84242-0\_24. 1, 2.5
- BCPS18. Anurag Bishnoi, Pete L. Clark, Aditya Potukuchi, and John R. Schmitt. On zeros of a polynomial in a finite grid. *Combinatorics, Probability and Computing*, 27(3):310–333, 2018. doi: 10.1017/S0963548317000566. 3
- BCPUNBL25. Iván Blanco-Chacón, Alberto Pedrouzo-Ulloa, Rahinatou Y. Njah Nchiwo, and Beatriz Barbero-Lucas. Fast polynomial arithmetic in homomorphic encryption with cyclo-multiquadratic fields. *Cryptography and Communications*, 17(4):741–775, July 2025. Publisher Copyright: © The Author(s) 2025. doi: 10.1007/s12095-024-00771-6. B.1
- BCTV14. Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, and Madars Virza. Scalable zero knowledge via cycles of elliptic curves. In Juan A. Garay and Rosario Gennaro, editors, *CRYPTO 2014, Part II*, volume 8617 of *LNCS*, pages 276–294. Springer, Berlin, Heidelberg, August 2014. doi: 10.1007/978-3-662-44381-1\_16. 1
- BDFG21. Dan Boneh, Justin Drake, Ben Fisch, and Ariel Gabizon. Halo infinite: Proof-carrying data from additive polynomial commitments. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part I*, volume 12825 of *LNCS*, pages 649–680, Virtual Event, August 2021. Springer, Cham. doi: 10.1007/978-3-030-84242-0\_23. 1
- BGH19. Sean Bowe, Jack Grigg, and Daira Hopwood. Halo: Recursive proof composition without a trusted setup. *Cryptology ePrint Archive*, Report 2019/1021, 2019. URL: <https://eprint.iacr.org/2019/1021>. 1
- BKS<sup>+</sup>21. Fabian Boemer, Sejun Kim, Gelila Seifu, Fillipe D.M. de Souza, and Vinodh Gopal. Intel hexl: Accelerating homomorphic encryption with intel avx512-ifma52. In *Proceedings of the 9th on Workshop on Encrypted Computing & Applied Homomorphic Cryptography*, WAHC '21, page 57–62, New York, NY, USA, 2021. Association for Computing Machinery. doi: 10.1145/3474366.3486926. C.2
- BL25. Katharina Boudgoust and Oleksandra Lapiha. Leftover hash lemma(s) over cyclotomic rings. *ASIACRYPT 2025*, to appear, 2025. B, B.2, 8
- BMNW25a. Benedikt Bünz, Pratyush Mishra, Wilson Nguyen, and William Wang. Accumulation without homomorphism. In Raghu Meka, editor, *ITCS 2025*, volume 325, pages 23:1–23:25. LIPIcs, January 2025. doi: 10.4230/LIPIcs.ITCS.2025.23. 1
- BMNW25b. Benedikt Bünz, Pratyush Mishra, Wilson Nguyen, and William Wang. Arc: Accumulation for reed-solomon codes. In Yael Tauman Kalai and Seny F. Kamara, editors, *CRYPTO 2025, Part VII*, volume 16006 of *LNCS*, pages 128–160. Springer, Cham, August 2025. doi: 10.1007/978-3-032-01907-3\_5. 1
- BN06. Mihir Bellare and Gregory Neven. Multi-signatures in the plain public-key model and a general forking lemma. In Ari Juels, Rebecca N. Wright, and Sabrina De Capitani di Vimercati, editors, *ACM CCS 2006*, pages 390–399. ACM Press, October / November 2006. doi: 10.1145/1180405.1180453. 6
- BS23. Ward Beullens and Gregor Seiler. LaBRADOR: Compact proofs for R1CS from module-SIS. In Helena Handschuh and Anna Lysyanskaya, editors, *CRYPTO 2023, Part V*, volume 14085 of *LNCS*, pages 518–548. Springer, Cham, August 2023. doi: 10.1007/978-3-031-38554-4\_17. 1, 4, 1.1, B.1
- CCC<sup>+</sup>25. Ignacio Cascudo, Anamaria Costache, Daniele Cozzo, Dario Fiore, Antonio Guimarães, and Eduardo Soria-Vazquez. Verifiable computation for approximate homomorphic encryption schemes. In Yael Tauman Kalai and Seny F. Kamara, editors, *CRYPTO 2025, Part VII*, volume 16006 of *LNCS*, pages 643–677. Springer, Cham, August 2025. doi: 10.1007/978-3-032-01907-3\_21. 1
- CCG<sup>+</sup>23. Megan Chen, Alessandro Chiesa, Tom Gur, Jack O'Connor, and Nicholas Spooner. Proof-carrying data from arithmetized random oracles. In Carmi Hazay and Martijn Stam, editors, *EUROCRYPT 2023, Part II*, volume 14005 of *LNCS*, pages 379–404. Springer, Cham, April 2023. doi: 10.1007/978-3-031-30617-4\_13. 1, 2.5
- CHK<sup>+</sup>21. Chi-Ming Marvin Chung, Vincent Hwang, Matthias J. Kannwischer, Gregor Seiler, Cheng-Jhih Shih, and Bo-Yin Yang. NTT multiplication for NTT-unfriendly rings. *IACR TCHES*, 2021(2):159–188, 2021. URL: <https://tches.iacr.org/index.php/TCHES/article/view/8791>, doi: 10.46586/tches.v2021.i2.159-188. 8
- CT10. Alessandro Chiesa and Eran Tromer. Proof-carrying data and hearsay arguments from signature cards. In Andrew Chi-Chih Yao, editor, *ICS 2010*, pages 310–331. Tsinghua University Press, January 2010. 1, 2.5

- EHRS24. Mohammed El-Hajj, Bjorn Roelink, and Dipti Sarmah. Systematic review: Comparing zk-snark, zk-stark, and bulletproof protocols for privacy-preserving authentication, 04 2024. doi:10.1002/spy2.401. 1
- FKNP24. Giacomo Fenzi, Christian Knabenhans, Ngoc Khanh Nguyen, and Duc Tu Pham. Lova: Lattice-based folding scheme from unstructured lattices. In Kai-Min Chung and Yu Sasaki, editors, *ASIACRYPT 2024, Part IV*, volume 15487 of *LNCS*, pages 303–326. Springer, Singapore, December 2024. doi:10.1007/978-981-96-0894-2\_10. 1
- FMN24. Giacomo Fenzi, Hossein Moghaddas, and Ngoc Khanh Nguyen. Lattice-based polynomial commitments: Towards asymptotic and concrete efficiency. *Journal of Cryptology*, 37(3):31, July 2024. doi:10.1007/s00145-024-09511-8. 6
- GKO24. Alberto Garoffolo, Dmytro Kaidalov, and Roman Oliynykov. Snarktor: A decentralized protocol for scaling SNARKs verification in blockchains. *Cryptology ePrint Archive*, Report 2024/099, 2024. URL: <https://eprint.iacr.org/2024/099>. 1
- GN08. Nicolas Gama and Phong Q. Nguyen. Predicting lattice reduction. In Nigel P. Smart, editor, *EUROCRYPT 2008*, volume 4965 of *LNCS*, pages 31–51. Springer, Berlin, Heidelberg, April 2008. doi:10.1007/978-3-540-78967-3\_3. C.1
- HYJ<sup>+</sup>25. Syed Mahbub Hafiz, Bahattin Yildiz, Marcos A. Simplicio Jr, Thales B. Paiva, Henrique Ogawa, Gabrielle De Micheli, and Eduardo L. Cominetti. Incompleteness in number-theoretic transforms: New tradeoffs and faster lattice-based cryptographic applications. *Cryptology ePrint Archive*, Paper 2025/768, 2025. URL: <https://eprint.iacr.org/2025/768>. 8
- KLNO24. Michael Kloß, Russell W. F. Lai, Ngoc Khanh Nguyen, and Michal Osadnik. RoK, paper, SISors toolkit for lattice-based succinct arguments - (extended abstract). In Kai-Min Chung and Yu Sasaki, editors, *ASIACRYPT 2024, Part V*, volume 15488 of *LNCS*, pages 203–235. Springer, Singapore, December 2024. doi:10.1007/978-981-96-0935-2\_7. 1, 4, 2.3, 1
- KLNO25a. Michael Kloß, Russell W. F. Lai, Ngoc Khanh Nguyen, and Michal Osadnik. RoK and roll - verifier-efficient random projection for  $\tilde{O}(\lambda)$ -size lattice arguments - (extended abstract). In Goichiro Hanaoka and Bo-Yin Yang, editors, *ASIACRYPT 2025, Part III*, volume 16247 of *LNCS*, pages 297–329. Springer, Singapore, December 2025. doi:10.1007/978-981-95-5099-9\_10. 2.3
- KLNO25b. Michael Kloß, Russell W. F. Lai, Ngoc Khanh Nguyen, and Michal Osadnik. Rok and roll. *ASIACRYPT 2025*, to appear, 2025. 1, 1.1, 2
- KP22. Abhiram Kothapalli and Bryan Parno. Algebraic reductions of knowledge. *Cryptology ePrint Archive*, Report 2022/009, 2022. URL: <https://eprint.iacr.org/2022/009>. 1
- KS24. Abhiram Kothapalli and Srinath T. V. Setty. HyperNova: Recursive arguments for customizable constraint systems. In Leonid Reyzin and Douglas Stebila, editors, *CRYPTO 2024, Part X*, volume 14929 of *LNCS*, pages 345–379. Springer, Cham, August 2024. doi:10.1007/978-3-031-68403-6\_11. 1, 2.6, 7.3
- LM25. Jia Liu and Mark Manulis. Fast snark-based non-interactive distributed verifiable random function with ethereum compatibility. In *Proceedings of the 20th ACM Asia Conference on Computer and Communications Security*, ASIA CCS '25, page 807–822, New York, NY, USA, 2025. Association for Computing Machinery. doi:10.1145/3708821.3710835. 1
- LS18. Vadim Lyubashevsky and Gregor Seiler. Short, invertible elements in partially splitting cyclotomic rings and applications to lattice-based zero-knowledge proofs. In Jesper Buus Nielsen and Vincent Rijmen, editors, *EUROCRYPT 2018, Part I*, volume 10820 of *LNCS*, pages 204–224. Springer, Cham, April / May 2018. doi:10.1007/978-3-319-78381-9\_8. 4, 1.1, B, B.1, 6, 1
- LSS<sup>+</sup>21. Zhichuang Liang, Shiyu Shen, Yiantao Shi, Dongni Sun, Chongxuan Zhang, Guoyun Zhang, Yunlei Zhao, and Zhixiang Zhao. Number theoretic transform: Generalization, optimization, concrete analysis and applications. In Yongdong Wu and Moti Yung, editors, *Information Security and Cryptology*, pages 415–432, Cham, 2021. Springer International Publishing. 8
- LZW<sup>+</sup>24. Xuanming Liu, Zhelei Zhou, Yinghao Wang, Bingsheng Zhang, and Xiaohu Yang. Scalable collaborative zk-SNARK: Fully distributed proof generation and malicious security. *Cryptology ePrint Archive*, Report 2024/143, 2024. URL: <https://eprint.iacr.org/2024/143>. 1
- LZW<sup>+</sup>25. Xuanming Liu, Zhelei Zhou, Yinghao Wang, Yanxin Pang, Jinye He, Bingsheng Zhang, Xiaohu Yang, and Jiaheng Zhang. Scalable collaborative zk-snark and its application to fully distributed proof delegation. In *Proceedings of the 34th USENIX Conference on Security Symposium*, SEC '25, USA, 2025. USENIX Association. 1
- NPR19. Moni Naor, Omer Paneth, and Guy N. Rothblum. Incrementally verifiable computation via incremental PCPs. In Dennis Hofheinz and Alon Rosen, editors, *TCC 2019, Part II*, volume 11892 of *LNCS*, pages 552–576. Springer, Cham, December 2019. doi:10.1007/978-3-030-36033-7\_21. 1, 2.5

- NS24. Ngoc Khanh Nguyen and Gregor Seiler. Greyhound: Fast polynomial commitments from lattices. In Leonid Reyzin and Douglas Stebila, editors, *CRYPTO 2024, Part X*, volume 14929 of *LNCS*, pages 243–275. Springer, Cham, August 2024. doi:10.1007/978-3-031-68403-6\_8. B.1
- NS25. Wilson Nguyen and Srinath Setty. Neo: Lattice-based folding scheme for CCS over small fields and pay-per-bit commitments. *Cryptology ePrint Archive*, Report 2025/294, 2025. URL: <https://eprint.iacr.org/2025/294>. 1, 1, 1.1, 2.6, 7, 7.2, 7.3
- Ped92. Torben P. Pedersen. Non-interactive and information-theoretic secure verifiable secret sharing. In Joan Feigenbaum, editor, *CRYPTO'91*, volume 576 of *LNCS*, pages 129–140. Springer, Berlin, Heidelberg, August 1992. doi:10.1007/3-540-46766-1\_9. 1
- PMH<sup>+</sup>25. Thales B. Paiva, Gabrielle De Micheli, Syed Mahbub Hafiz, Marcos A. Simplicio Jr., and Bahattin Yildiz. Faster amortized bootstrapping using the incomplete NTT for free. *Cryptology ePrint Archive*, Paper 2025/696, 2025. URL: <https://eprint.iacr.org/2025/696>. 8
- PS00. David Pointcheval and Jacques Stern. Security arguments for digital signatures and blind signatures. *Journal of Cryptology*, 13(3):361–396, June 2000. doi:10.1007/s001450010003. 6
- Res24. Nethermind Research. Latticefold and lattice-based operations performance report, 2024. URL: <https://nethermind.notion.site/Latticefold-and-lattice-based-operations-performance-report-153360fc38d080ac930cdeeffed69559>. 1
- Sho94. Peter W. Shor. Algorithms for quantum computation: Discrete logarithms and factoring. In *35th FOCS*, pages 124–134. IEEE Computer Society Press, November 1994. doi:10.1109/SFCS.1994.365700. 1
- STW23. Srinath Setty, Justin Thaler, and Riad Wahby. Customizable constraint systems for succinct arguments. *Cryptology ePrint Archive*, Report 2023/552, 2023. URL: <https://eprint.iacr.org/2023/552>. 7.2
- Val08. Paul Valiant. Incrementally verifiable computation or proofs of knowledge imply time/space efficiency. In Ran Canetti, editor, *TCC 2008*, volume 4948 of *LNCS*, pages 1–18. Springer, Berlin, Heidelberg, March 2008. doi:10.1007/978-3-540-78524-8\_1. 1, 2.5
- XZC<sup>+</sup>22. Tiancheng Xie, Jiaheng Zhang, Zerui Cheng, Fan Zhang, Yupeng Zhang, Yongzheng Jia, Dan Boneh, and Dawn Song. zkBridge: Trustless cross-chain bridges made practical. In Heng Yin, Angelos Stavrou, Cas Cremers, and Elaine Shi, editors, *ACM CCS 2022*, pages 3003–3017. ACM Press, November 2022. doi:10.1145/3548606.3560652. 1
- ZSCZ25. Jiaxing Zhao, Srinath T. V. Setty, Weidong Cui, and Greg Zaverucha. MicroNova: Folding-based arguments with efficient (on-chain) verification. In Marina Blanton, William Enck, and Cristina Nita-Rotaru, editors, *2025 IEEE Symposium on Security and Privacy*, pages 1964–1982. IEEE Computer Society Press, May 2025. doi:10.1109/SP61157.2025.00168. 1

# A Extended Preliminaries

## A.1 Variants of Principal Linear Relation

Below, we define a variant of the principal linear relation from Section 3 that includes an additional “slack” variable  $s$ , which is a (short) denominator of the witness  $\mathbf{w}$ . This variant is useful particularly in the security proof of our folding scheme, where the extractor may only be able to extract a witness  $\mathbf{w}$  that is “close” to the relation, i.e.  $\mathbf{A}\mathbf{w} = \mathbf{y} \cdot s \bmod q$  for some small  $s \in \mathcal{R}_q^\times$ .

$$\Xi_{\mathbf{A}, (\mathbf{M}_i)_{i \in [k]}, a, n, m, B, \varrho}^{\text{lin-slack}} := \left\{ \begin{array}{c} \overline{((\mathbf{r}_i)_{i \in [k]}, (\mathbf{b}_i)_{i \in [n]}, \mathbf{y}), (\mathbf{w}, s) :} \\ \left( \mathbf{M}_i \in \mathcal{R}_q^{m_i \times m}, \mathbf{r}_i \in \mathcal{R}_q^{\log m_i} \right)_{i \in [k]}, (\mathbf{b}_i \in \mathcal{R}_q^{\log m})_{i \in [n]}, \\ \mathbf{A} \in \mathcal{R}_q^{a \times m}, \mathbf{y} := \begin{pmatrix} \bar{\mathbf{y}} \in \mathcal{R}_q^a \\ \underline{\mathbf{y}} \in \mathcal{R}_q^{k+n} \end{pmatrix}, \mathbf{w} \in \mathcal{R}_q^m, s \in \mathcal{R}_q^\times \\ \begin{pmatrix} \mathbf{A} \\ \text{tensor}(\mathbf{r}_0)^\top \mathbf{M}_0 \\ \vdots \\ \text{tensor}(\mathbf{r}_{k-1})^\top \mathbf{M}_{k-1} \\ \text{tensor}(\mathbf{b}_0)^\top \\ \vdots \\ \text{tensor}(\mathbf{b}_{n-1})^\top \end{pmatrix} (w/s) = \mathbf{y} \bmod q \\ \|\mathbf{w}\| \leq B, \quad \|s\|_\infty \leq \varrho \end{array} \right\},$$

## A.2 SIS-break Relation

We also define a relation that captures the hardness of the SIS problem, which we will use in the security proof of our folding scheme. The relation is a simple variant of the principal linear relation with no additional constraints, i.e.  $k = n = 0$  and with a zero image vector, i.e.  $\mathbf{y} = \mathbf{0}$ .

$$\Xi_{\mathbf{A}, a, m, B}^{\text{sis}} := \left\{ \begin{array}{c} \overline{\cdot, \mathbf{w} :} \\ \mathbf{A} \in \mathcal{R}_q^{a \times m}, \mathbf{w} \in \mathcal{R}_q^m \\ \mathbf{A}\mathbf{w} = \mathbf{0} \bmod q \\ \|\mathbf{w}\| \leq B \\ \mathbf{w} \neq \mathbf{0} \end{array} \right\}.$$

## A.3 Reduction of Knowledge

**Definition 1 (Reduction of Knowledge (adapted from [KLNO24])).** Let  $\Xi_0, \Xi_1$  be ternary relations. A reduction of knowledge (RoK)  $\Pi$  from  $\Xi_0$  to  $\Xi_1$ , short  $\Pi : \Xi_0 \rightarrow \Xi_1$ , is defined by two PPT algorithms  $\Pi = (\mathbf{P}, \mathbf{V})$ , the prover  $\mathbf{P}$  and the verifier  $\mathbf{V}$ , with the following interface:

- $\mathbf{P}(\text{pp}, \mathbf{x}, \mathbf{w}) \rightarrow (\tilde{\mathbf{x}}, \tilde{\mathbf{w}})$ : Interactively reduce the input statement-witness tuple  $(\text{pp}, \mathbf{x}, \mathbf{w}) \in \Xi_0$  to a new statement-witness tuple  $(\text{pp}, \tilde{\mathbf{x}}, \tilde{\mathbf{w}}) \in \Xi_1$  or  $\perp$ .
- $\mathbf{V}(\text{pp}, \mathbf{x}) \rightarrow \tilde{\mathbf{x}}$ : Interactively reduce the task of checking the input statement  $(\text{pp}, \mathbf{x})$  w.r.t.  $\Xi_0$  to checking a new statement  $(\text{pp}, \tilde{\mathbf{x}})$  w.r.t.  $\Xi_1$ .

A RoK  $\Pi$  is *correct*, if for any honest protocol run (with correct inputs), the prover outputs a witness for the reduced statement (which the verifier outputs). A RoK  $\Pi$  is *knowledge sound* from  $\Xi_0^{\text{KS}}$  to  $\Xi_1^{\text{KS}}$  with knowledge error  $\kappa(\text{pp}, \mathbf{x})$  if there is a black-box expected polynomial-time extractor  $\mathcal{E}$ , which succeeds with probability  $\epsilon - \kappa(\text{pp}, \mathbf{x})$  if the malicious prover outputs a valid witness for the reduced statement with probability  $\epsilon$  (on verifier's input  $(\text{pp}, \mathbf{x})$ ).

**Definition 2 (Knowledge soundness).** A reduction of knowledge  $\Pi = (\mathbf{P}^*, \mathbf{V})$  from  $\Xi_0$  to  $\Xi_1$  is knowledge sound with knowledge error  $\kappa : \mathbb{N} \rightarrow [0, 1]$  if there exists a knowledge extractor  $\mathcal{E}$ ,

such that for every statement  $x \in \Xi_0$  and any prover  $P^*$ , the extractor  $\mathcal{E}^{P^*}(x)$  runs in expected time polynomial in  $|x|$  (counting calls to  $P^*$  as unit-cost operations) and outputs a witness  $w$  such that

$$\Pr(x; \mathcal{E}^{P^*}(x) \in \Xi_0) \geq \epsilon(P^*, x) - \kappa(|x|),$$

where  $\epsilon(P^*, x) := \Pr \Xi_1 \leftarrow (P^*, V)(x)$

# B Instantiation of Strong Sampling Set

We first state a lemma showing that the differences of two elements sampled from the biased ternary distribution are invertible with high probability.

We discuss two instantiations of the low-norm challenge distribution for concrete parameters. First, we consider a well-established instantiation based on [LS18] and show that it yields an exact strong sampling set. Then, we discuss a heuristic instantiation based on [BL25] that yields an approximate strong sampling set.

## B.1 Exact Strong Sampling Set

We recall the following theorem from [LS18] that characterizes the factorization of cyclotomic polynomials over finite fields.

**Theorem 6 (Theorem 1 from [LS18]).** *Let  $\mathcal{R} = \mathbb{Z}[X]/\langle \Phi_{\mathfrak{f}}(X) \rangle$  be a cyclotomic ring with conductor  $\mathfrak{f}$  and  $\varphi = \varphi(\mathfrak{f})$ . Let  $\mathcal{R}_q = \mathcal{R}/q\mathcal{R}$ . Let  $\mathfrak{f} = \prod p_i^{e_i}$  for  $e_i \geq 1$  and  $z = \prod p_i^{f_i}$  for  $1 \leq f_i \leq e_i$ . If  $q$  is a prime such that  $q \equiv 1 \pmod{z}$  and  $\text{ord}_m(q) = \mathfrak{f}/z$ , then the polynomial  $\Phi_{\mathfrak{f}}(X)$  factors as*

$$\Phi_{\mathfrak{f}}(X) = \prod_{j \in [\varphi(z)]} \left( X^{\mathfrak{f}/z} - r_j \right) \pmod{q},$$

for distinct  $r_j \in \mathbb{Z}_q^\times$ , where  $X^{\mathfrak{f}/z} - r_j$  are irreducible  $\pmod{q}$ . Furthermore, any  $y \in \mathcal{R}_q$  that satisfies either

$$0 < \|y\|_\infty < \frac{1}{s_1(z)} q^{1/\varphi(z)} \quad \text{or} \quad 0 < \|y\|_2 < \frac{q^{\varphi(m)}}{s_1(\mathfrak{f})} q^{1/\varphi(z)}$$

has an inverse in  $\mathcal{R}_q$ .

Further, this theorem is specialized to power-of-two cyclotomic rings in the following corollary.

**Corollary 1 (Corollary 1.2 from [LS18]).** *Let  $\mathcal{R} = \mathbb{Z}[X]/\langle X^\varphi + 1 \rangle$  be a cyclotomic ring with conductor  $\mathfrak{f} = 2\varphi$ . Let  $\varphi \geq k > 1$  be powers of 2 and  $q = 2k + 1 \pmod{4k}$  be a prime. Then the polynomial  $X^\varphi + 1$  factors as*

$$X^\varphi + 1 = \prod_{j \in [k]} \left( X^{\varphi/k} - r_j \right) \pmod{q}$$

for distinct  $r_j \in \mathbb{Z}_q^\times$ , where  $X^{\varphi/k} - r_j$  are irreducible in the ring  $\mathbb{Z}_q[X]$ . Furthermore, any  $y \in \mathbb{Z}_q[X]/\langle X^\varphi + 1 \rangle$  that satisfies either

$$0 < \|y\|_\infty < \frac{1}{\sqrt{k}} \cdot q^{1/k} \quad \text{or} \quad 0 < \|y\|_2 < q^{1/k}$$

has an inverse in  $\mathbb{Z}_q[X]/\langle X^\varphi + 1 \rangle$ .

Therefore, we can instantiate a strong sampling set  $\mathcal{C}$  in  $\mathcal{R}_q$  of norm  $\gamma$ . More precisely, we present the following lemma.

**Lemma 7.** *Repeating the setting from Theorem 6 (resp., Corollary 1), we let  $\mathcal{C}$  be the uniform distribution over elements  $c \in \mathcal{R}_q$  such that*

$$\|c\|_\infty \leq \beta < \frac{1}{2s_1(z)} q^{1/\varphi(z)} \quad (\text{resp., } \|c\|_\infty \leq \beta < \frac{1}{2\sqrt{k}} \cdot q^{1/k}).$$

*Then  $\mathcal{C}$  is an exact strong sampling set of norm  $\beta\gamma_\infty$ , where  $\gamma_\infty$  is the operator norm of multiplication in  $\mathcal{R}$  under the infinity norm. The cardinality of  $\mathcal{C}$  is  $(2\beta + 1)^\varphi$ .*

*Proof.* By subadditivity of the infinity norm, for any  $c_1, c_2 \in \mathcal{C}$  we have

$$\|c_1 - c_2\|_\infty \leq \|c_1\|_\infty + \|c_2\|_\infty \leq 2\beta < \frac{1}{s_1(z)} q^{1/\varphi(z)} \quad (\text{resp., } 2\beta < \frac{1}{\sqrt{k}} \cdot q^{1/k}).$$

Therefore, by Theorem 6 (resp., Corollary 1),  $c_1 - c_2$  is invertible in  $\mathcal{R}_q$ . The bound on the operator norm follows directly from the definition.

*Remark 7.* In the context of power-of-two cyclotomic rings, the challenge set is restricted by using only a subset of coefficients. Then, the operator norm can be expressed as  $\beta h$ , where  $h$  is the Hamming weight, i.e., the number of non-zero coefficients in the polynomial representation of an element in  $\mathcal{C}$ . The cardinality of  $\mathcal{C}$  is then  $(2\beta + 1)^h$ .

Nevertheless, this instantiation has a drawback: the lack of splitting imposes a significant computational overhead. To exemplify, let  $q$  be a 50-bit prime and  $f = 256$  so that  $\varphi = 128$ . Then, we want to instantiate a strong sampling set with ternary challenges so that the cardinality of  $\mathcal{C}$  would be enough for, e.g., 80-bit statistical security. After performing the calculations, we find the maximal value of  $k$  is 16 (otherwise, the permitted  $\ell_\infty$ -norm of the challenge set is below 2). Therefore, the polynomial  $X^{128} + 1$  splits only down to degree-8 polynomials over  $\mathbb{Z}_q$ . In this setting, a simple NTT-based multiplication does not yield a reasonable speed-up, and for efficient multiplication, we could employ RNS representation with multiple moduli  $p_i$  where  $X^\varphi + 1$  splits [BCPUNBL25]. This approach has been used in practice, e.g., in [BS23,NS24].

## B.2 Approximate Strong Sampling Set

We discuss a heuristic instantiation of an approximate strong sampling set based on the recent results [BL25].

We recall the definition of the biased ternary distribution.

**Definition 3 (Biased Ternary Distribution).** *Let  $\chi$  denote the biased ternary distribution with bias  $p \in [0, 1]$  over  $\{-1, 0, 1\}$ . This distribution samples 0 with probability  $p$  and  $\pm 1$  with probability  $(1 - p)/2$ .*

Then, we have the following lemma, which shows that the differences of two elements sampled from the biased ternary distribution are invertible with high probability.

**Lemma 8 (Adapted Lemma 32 from [BL25] and generalized from [ALS20] Lemma 3.2).** *Let  $\mathcal{R} = \mathbb{Z}[X]/\langle \Phi_f(X) \rangle$  be the  $f$ -th cyclotomic ring with degree  $\varphi = \varphi(f)$ . Further, let  $f = \prod p_i^{e_i}$*

for  $e_i \geq 1$  and  $z = \prod p_i^{f_i}$  for  $1 \leq f_i \leq e_i$ . Let  $q$  be a prime such that  $q = 1 \pmod{z}$  and the multiplicative order of  $q$  modulo  $\mathfrak{f}$  is  $\mathfrak{f}/z$ . By Theorem 6,  $\Phi_{\mathfrak{f}}(X)$  factors as

$$\Phi_{\mathfrak{f}}(X) = \prod_{j \in [k]} \left( X^{\varphi/k} - r_j \right) = \prod_{j \in [k]} \Phi_j(X) \pmod{q},$$

for distinct  $r_j \in \mathbb{Z}_q^\times$ . Let  $\chi$  be the distribution over  $\mathcal{S} = \{c \in \mathcal{R}_q : \|c\|_\infty \leq 1\}$  where each coefficient of the polynomial is sampled from the biased ternary distribution  $\chi$ , i.e.,  $\mathcal{P} = \chi^\varphi$ . The distribution  $\chi$  is  $\epsilon$ -well-spread, meaning that for all  $j \in [k]$  and for all  $y \in \mathbb{Z}_q[X]/\langle \Phi_j(X) \rangle$ , it holds that

$$\Pr[x \bmod \Phi_j(X) = y \mid x \leftarrow \mathcal{P}] \leq \epsilon,$$

where  $\epsilon$  is given by

$$\epsilon = \max_{j \in [k]} \left( \frac{1}{q} + \frac{1}{q} \sum_{t \in [q-1]} \prod_{i \in [k]} \left| p + (1-p) \cos \left( \frac{2\pi(t+1)r_j^i}{q} \right) \right| \right)^{\varphi/k}.$$

Finally, we can instantiate an approximate strong sampling set as follows. We note that this lemma is specialized to power-of-two cyclotomic rings, and we leave the generalization to arbitrary cyclotomic rings for future work.

**Lemma 9 (Heuristic).** *Let  $\mathcal{R} = \mathbb{Z}[X]/\langle X^\varphi + 1 \rangle$  be the  $\mathfrak{f}$ -th cyclotomic ring with  $\mathfrak{f} = 2\varphi$ . Let  $\varphi \geq k > 1$  be powers of two and  $q = 2k + 1 \pmod{4k}$  be a prime. Let  $\mathcal{P}$  be the distribution over  $\mathcal{S} = \{c \in \mathcal{R}_q : \|c\|_\infty \leq 1\}$  where each coefficient of the polynomial is sampled from the biased ternary distribution with bias  $p = 1/3$ , i.e.,  $\mathcal{P} = \chi^\varphi$ . Then,  $\mathcal{P}$  is a uniform (since values  $-1, 0$ , and  $1$  are equally likely) distribution over an  $\kappa_{\text{nu}}$ -approximate strong sampling set with  $\kappa_{\text{nu}} \approx k/q^{\varphi/k}$ .*

*Proof.* The proof follows directly from Lemma 8. Except with probability  $\kappa_{\text{nu}}$ , the difference of two elements sampled from  $\mathcal{P}$  is invertible in each NTT slot (and therefore in the ring  $\mathcal{R}_q$ ). The value of  $\kappa_{\text{nu}}$  can be estimated using results from Table 1 of [ALS20], which we heuristically extend for  $\varphi/k > 1$ .

We support the heuristic of Lemma 9 with experimental results available at <https://github.com/osdnk/cyclo/blob/main/invertibility.ipynb>.

*Remark 8.* For very concrete parameters, let  $q$  be a 50-bit prime so that the cyclotomic ring splits down to quadratic extension fields, i.e.,  $\mathcal{R}_q \cong (\mathbb{F}_{q^2})^{\varphi/2}$  and  $\mathfrak{f} = 256$  so that  $\varphi = 128$  (as we use in our benchmarking). Then, we can instantiate an approximate strong sampling set  $\mathcal{C}$  by sampling each coefficient from the biased ternary distribution with bias  $p = 1/3$  (so that the values  $-1, 0$ , and  $1$  are equally likely). Following Lemma 9, we can expect that the probability of sampling a pair such that the difference is non-invertible is around  $2^{-94}$ , which is negligible compared with the statistical error, e.g.,  $\kappa = 2^{-80}$ . Such a distribution allows the use of NTT-based multiplication almost directly (albeit with a small overhead due to splitting only down to quadratic extension fields). This NTT, also known as the incomplete NTT, has been used in practice, e.g., in FHE-related works, and shown to be concretely efficient [CHK<sup>+</sup>21, LSS<sup>+</sup>21, HYJ<sup>+</sup>25, PMH<sup>+</sup>25].

# C Parameters Selection and Practical Evaluation

The goal of this section is to provide a practical evaluation of the proposed folding scheme and compare it with the state-of-the-art folding scheme from [BC25b]. We start with parameter selection and then provide a benchmark of the most computationally expensive part of the folding scheme, i.e., commitment computation.

## C.1 Communication

For parameter selection, we follow the approach from [BC25b] and use `LatticeEstimator` [APS15]. We consider a very similar parameter regime to [BC25b], namely  $\varphi \cdot m = 2^{27}$  coefficients in  $\mathbb{Z}_q$  for the witness and bound  $B = 2^{10}$ . We use  $b = 1$ , i.e., the decomposition base for the extension commitment so that the witness is decomposed to ternary digits. We set parameter ( $k = 3$ ) to emulate the R1CS reduction.

We slightly modify the parameter regime to account for faster concrete efficiency. In particular, we set the degree of the cyclotomic ring to  $\varphi = 128$  (instead of 64 in [BC25b]) and compensate with a smaller witness size  $m = 2^{20}$  (instead of  $m = 2^{21}$ ), so that the number of  $\mathbb{Z}_q$  elements remains the same. On the other hand, we use a smaller modulus  $q \approx 2^{50}$  (instead of  $2^{128}$  in [BC25b]), which impacts rank selection. We summarize the parameter comparison in Table 2.

| Parameter                                                   | LatticeFold+ [BC25b]      | Our Protocol                 |
|-------------------------------------------------------------|---------------------------|------------------------------|
| Rank ( $a$ )                                                | 9                         | 13                           |
| Modulus ( $q$ )                                             | $\approx 2^{128}$         | $\approx 2^{50}$             |
| Degree ( $\varphi$ )                                        | 64                        | 128                          |
| Folding Depth ( $T$ )                                       | $\infty$                  | 64                           |
| Initial Norm ( $B$ )                                        | $2^{10}$                  | $2^{10}$                     |
| Challenge Distribution                                      | $\{-1, 0, 1, 2\}^\varphi$ | $\{-1, 0, 1\}^\varphi$       |
| Witness Size ( $m$ )                                        | $2^{21}$                  | $2^{20}$                     |
| Number of $\mathbb{Z}_q$ coefficients ( $\varphi \cdot m$ ) | $2^{27}$                  | $2^{27}$                     |
| Number of relations to fold                                 | 2 (accumulator) + 1       | 1 (accumulator) + 1          |
| Other parameters                                            | $L = 3$                   | $e = 2, L = 1, k = 3, n = 1$ |
| Proof Size                                                  | 100 KB                    | 31.8 KB                      |

**Table 2.** Comparison of parameters between LatticeFold+ [BC25b] and our protocol. Proof estimates of [BC25b] are taken from the original paper, while our proof size is estimated using the communication complexity from Theorem 3 and the parameters above.

The rank of the Ajtai commitment has been selected according to the root Hermite factor  $\delta_0 = 1.0045$  corresponding to 128-bit security level and applying the BKZ reduction [GN08] after translating the  $\ell_\infty$  norm to the  $\ell_2$  norm. The computation has been performed using `LatticeEstimator` [APS15].

*Remark 9.* Increasing the number of folding rounds  $T$  increases the proof size only logarithmically. Practically, the number of rounds can be increased to  $2^{10}$  with negligible impact on the proof size, raising it to around 39.7 KB. Increasing the number of rounds to  $2^{20}$  raises the proof size to around 41.7 KB. Modifying the security levels shall be viewed independently for security parameter ( $\lambda$ ) and soundness error ( $\kappa$ ). The former one impacts (almost linearly) the rank selection ( $a, a'$ ). For concrete parameters from Table 2, increasing the security level to 256 bits raises the proof size to around 40.4 KB. Soundness error might be decreased by either increasing the modulus  $q$  or increasing the parameter  $e$  so that  $q^e \approx 1/\kappa$ , where  $\kappa$  is a desired soundness error. The “homogenization sumcheck” communication cost depends on  $e$  linearly. For the concrete parameters from Table 2, decreasing the soundness error to  $2^{-200}$  by increasing  $e$  to 4 raises the proof size to around 52.4 KB. While simultaneously increasing the security level to 256 bits and decreasing the soundness error to  $2^{-200}$  raises the proof size to around 61 KB<sup>10</sup>.

<sup>10</sup> All of the values are derived via script <https://github.com/osdnk/cyclo/blob/main/estimates.ipynb>.

## C.2 Benchmark of the Extension Commitment and Comparison with Double Commitment from [BC25b]

For our benchmark, we compare commitment computation from [BC25b] (the “double commitment”) with our extension commitment. These two commitments are the most computationally expensive part of the folding scheme, so the benchmark gives a good indication of concrete efficiency.

For the most optimal performance, we choose to work with power-of-two cyclotomic rings. Power-of-two cyclotomic rings admit efficient arithmetic using the Number-Theoretic Transform (NTT), which is particularly well-suited for vectorisation. This allows us to leverage SIMD instructions and hardware acceleration, leading to significant performance improvements. Our implementation utilises Intel’s HEXL library [BKS<sup>+</sup>21], which provides AVX-512-accelerated operations for efficient polynomial arithmetic over these rings. For best performance, we select a modulus  $q \approx 2^{50}$  so that runtime is further improved using AVX-512-IFMA instructions available on modern Intel processors. Towards our performance disadvantage, we need to select a modulus  $q$  such that  $\mathcal{R}_q \cong (\mathbb{F}_{q^2})^{\varphi/2}$ , i.e. our cyclotomic ring splits into factors of degree 2. This is because we require the existence of a strong sampling set so that the inverse of any two elements is invertible. The discussion on the strong sampling set is presented in Section B. We select  $\mathcal{D}$  to be an approximate strong sampling set as in Lemma 9 with  $\kappa_{\text{nu}} \approx 2^{-100}$ , which is sufficient for our security level. We select  $\mathcal{C}$  to be the subfield  $\mathbb{F}_{q^2}$  embedded in  $\mathcal{R}_q$ , which is a strong sampling set (since for  $\mathcal{C}$  we are not concerned about the norm).

For practical evaluation, we consider only the most computationally expensive part of the folding scheme, i.e., computation of the “double commitment” for [BC25b] and the “extension commitment” for our protocol. This gives an unfair advantage to [BC25b], since we consider only commitment computation and ignore decomposition overhead. We estimate the cost of sum-check to be similar in both protocols. Further, we consider computing a single commitment, while for [BC25b] the commitment is computed at least three times in the folding scheme (twice for the accumulator and once for each additional relation folded), whereas in our protocol it is computed only once per folded relation (excluding the accumulator).

We consider more practical parameters as a baseline for [BC25b], i.e., we increase the degree of the cyclotomic ring to  $\varphi = 128$  and decrease the witness size to  $m = 2^{20}$ , so that the number of  $\mathbb{Z}_q$  elements remains  $2^{27}$ . We use modulus  $q \approx 2^{50}$  (to benefit from the same architecture optimizations as in our protocol). The rank is selected to provide a 128-bit security level, which results in  $a = 12$ .

We assess the cost of both commitments using benchmarks for the individual components. The results of the benchmark are presented in Table 3.

| Component                                                 | Runtime   |
|-----------------------------------------------------------|-----------|
| $T_{\text{ntt}}$ : Forward “incomplete NTTs”              | 179.03 ns |
| $T_+$ : Ring element addition (without modular reduction) | 40.077 ns |
| $T_q$ : Modular reduction                                 | 97.102 ns |
| $T_*$ : Ring element multiplication in NTT domain         | 186.53 ns |

**Table 3.** Benchmark results for the individual components of the commitment computation

Next, we estimate the costs of the two commitments. We use  $\ddagger$  as the maximum number of additions before reduction modulo  $q$  is required to avoid overflowing 60 bits (so Barrett reduction can still be applied efficiently). The calculations are summarized in Table 4. We note that these

numbers are only indicative because we do not consider the full protocol, although they serve as a reasonable approximation. We observe that our commitment is around  $3.53\times$  faster than the commitment from [BC25b]. Further speedup could be achieved by using a larger decomposition base (e.g., 4 instead of 2), which would slightly affect sum-check efficiency but speed up commitment computation. We leave this exploration for future work. We also remark that runtime was measured on a single thread, while the protocol could be parallelized to gain (almost) linear speedups from multiple cores.

## C.3 On the efficiency of Sum-check

We do not analyze sum-check efficiency in detail, mainly because the cost of sum-check in our protocol is expected to be similar to that in [BC25b]. In Remark 3, the cost of sum-check is ignored because, asymptotically, commitment cost dominates. However, in practice, the prover-side computational cost of sum-check is not negligible, so we provide a preliminary estimate for our protocol.

**Range-check sum-check** The range-check sum-check is performed over  $\ell = \lceil \log(\hat{m}\varphi) \rceil$  rounds with degree bound  $2b + 2$ . We write  $\hat{m} = m \log_{2b} 2B$  to account for witness decomposition. The sum-check protocol is executed over the extension field  $\mathbb{F}_{q^e}$ , so we measure cost in terms of  $\mathbb{F}_{q^e}$  operations. The function used in the sum-check is

$$\hat{f} = \omega \cdot \prod_{j \in [-b, b]} (\text{MLE}[\text{cf}(\mathbf{w})] - j),$$

where  $\omega$  is a “separator” (multilinear) polynomial as described in Fig. 1. We assume that the witness  $\mathbf{w}$  is given in the evaluation form over the boolean hypercube. We assume that  $b = 1$  so as to minimize the cost of sum-check, which is the case for our protocol. The computation of the univariate polynomial in the first round of sum-check requires computing  $\hat{m}\varphi/2$  interpolations of partially evaluated  $\hat{f}$ , denoted  $\hat{f}_i$  for  $i \in [\hat{m}\varphi/2]$ .  $\hat{f}_i$  is a product of partially evaluated  $\omega$  and partially evaluated  $\prod_{j \in [-1, 1]} (\text{MLE}[\text{cf}(\mathbf{w})] - j)$ . By exploiting  $(X - 1) \cdot X \cdot (X + 1) = (X^3 - X)$ , we can compute  $\hat{f}_i$  using 5 multiplications (using the Karatsuba identity and ignoring additions). Therefore, the cost of computing the univariate polynomial in the first round is about  $\hat{m}\varphi/2 \cdot 5$  multiplications over  $\mathbb{F}_{q^e}$ . Then, by geometric progression in sum-check, the total cost of computing univariate polynomials across all rounds is about  $6\hat{m}\varphi$  multiplications over  $\mathbb{F}_{q^e}$  (the first round and subsequent folding dominate). Translated to multiplications over  $\mathcal{R}_{q^e}$ , the cost is around  $6\hat{m}e \mathcal{R}_q$  multiplications. For the concrete parameters from Table 2, this is slightly smaller than commitment cost, since  $6e = 12$  is smaller than rank  $a = 13$ .

**Sum-check for the unification of challenges** The sum-check for the unification of challenges is performed over  $\ell = \lceil \log(m\varphi(\log_{2b} 2B)) \rceil$  rounds with degree bound 2. We write  $\hat{m} = m \log_{2b} 2B$  to account for the witness decomposition. According to the description of the sum-check in Section 6, from the prover’s perspective, the cost of the sum-check is equivalent to performing  $2 + k + L \cdot (k + 2)$  sum-check claims over  $\mathcal{R}_{q^e}$ . However, except for the last claim, i.e.,  $\sum_{\mathbf{z} \in \{0, 1\}^{\log \hat{m}}} \text{MLE}[\mathbf{v}](\mathbf{z}) \text{eq}(\mathbf{z}; \mathbf{b}) = y_{a'+k+1}$ , all other sum-check claims are either highly structured (since  $\mathbf{v}'_j$  and  $\widehat{\mathbf{M}}_i$  have been subject to decomposition or tensor-extensions, and therefore  $\widehat{\mathbf{M}}_i \cdot \mathbf{v}'_j = \mathbf{M}_i \mathbf{v}_j$ ), or can be pre-computed

from previous round (or are trivial in the case of an empty accumulator for the first round) and have shorter dimension as in the case of  $\widehat{\mathbf{M}}_i \mathbf{v}$ . Therefore, the cost of computing the sum-check is dominated by the cost of the last claim. This claim is of degree 2, and the cost of computing the univariate polynomial in the first round is approximately  $\hat{m}/2 \cdot 3$  multiplications over  $\mathcal{R}_{q^e}$  (the factor 3 comes from exploiting the Karatsuba identity for polynomial multiplication). Thus, we upper bound the total cost of computing the univariate polynomials in all rounds by about  $4\hat{m}$  multiplications over  $\mathcal{R}_{q^e}$ , which is computationally equivalent to around  $4\hat{m}e$  multiplications over  $\mathcal{R}_q$ . For the concrete parameters from Table 2, this cost is smaller than the cost of the commitment computation, since  $4e = 8$  is less than the rank  $a = 13$ .

We remark that these are preliminary estimates, and the actual cost of sum-check may be lower due to various optimizations (e.g. exploiting the structure of the target function in sum-check, or using fast algorithms for polynomial evaluation and interpolation). We leave a more detailed analysis for future work. The crucial observation is that even ignoring the cost of sum-check for [BC25b], the cost of “double commitment” still dominates the cost of Cyclo, including the cost of sum-check and the cost of the extension commitment.

## C.4 Memory usage

None of the schemes considered (neither [BC25b,BC25a] nor our protocol) aims to be memory-efficient from the prover’s perspective, so memory usage is not expected to be optimized. Executing our folding scheme requires storing (and running sum-check on)  $(L + 1)m \log_{2b} 2B$  ring elements (1.56GB for the parameters from Table 2). This is similar to the memory usage of [BC25a]. On the other hand, the folding scheme from [BC25b] requires storing (and running sum-check on)  $(L + 1)m\varphi \log_{\varphi} B$  ring elements (16GB for the parameters from Table 2). However, that scheme executes sum-check over constant monomials, so memory usage is expected to be lower in practice (optimistic estimates suggest around 256MB, albeit with computational overhead due to sparse polynomial representation). We leave a more detailed memory analysis for future work.

| Protocol                  | Expression                                                                                                | Concrete Time |
|---------------------------|-----------------------------------------------------------------------------------------------------------|---------------|
| Double commitment [BC25b] | $(k \cdot \varphi \cdot m \cdot a) \cdot (\mathsf{T}_+ + \mathsf{T}_q/\sharp)$                            | 129.4 s       |
| Extension commitment      | $(m \log_{2b} 2B) \cdot (\mathsf{T}_{\text{ntt}} + a(\mathsf{T}_* + \mathsf{T}_+ + \mathsf{T}_q/\sharp))$ | 36.7 s        |

**Table 4.** Benchmark results for the double commitment from [BC25b] and our extension commitment.

The system specification used for test execution is summarized in Table 5. The codebase is available at <https://github.com/osdnk/cyclo>.

|                            |                                                        |
|----------------------------|--------------------------------------------------------|
| Node type                  | Dell PowerEdge XE8640                                  |
| CPU                        | 2x48 core Xeon Platinum 8468 2.1GHz<br>Sapphire Rapids |
| Virtual cores (total/used) | 192/1                                                  |
| Memory                     | 1024GB DDR5-4800                                       |
| OS                         | CentOS 7                                               |

**Table 5.** Specifications of the node used for experiments.