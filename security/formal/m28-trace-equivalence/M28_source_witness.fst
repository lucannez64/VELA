module M28_source_witness

(* Non-vacuity at source level: one concrete trace of the original
   seven-rule M28 source system, satisfying the Increasing restriction, that
   witnesses both exists-trace lemmas (recovery_is_reachable and
   two_successive_commits_advance).  Lifted, it is also a trace of the
   Chain-instrumented system.  It uses the real attacker: the two journal
   inputs <successor('initial'), 'p1'> and
   <successor(successor('initial')), 'p2'> are derived with [derivable]
   from public names, and the four fresh names come from the Fresh rule.

     #0  Fresh ~s            #9  ClearJournal       JournalCleared
     #1  Fresh ~i            #10 OpenVault          Opened
     #2  Initialize          #11 Fresh ~t2
     #3  Fresh ~t1           #12 ReadSnapshot
     #4  ReadSnapshot        #13 isend <n2, 'p2'>
     #5  isend <n1, 'p1'>    #14 PersistJournal     JournalDurable
     #6  PersistJournal      #15 PersistVault       VaultDurable
     #7  Crash               #16 ClearJournal       JournalCleared
     #8  PersistVault                                                    *)

open M28_source_terms
open M28_source_semantics
open M28_source_bridge

module L = FStar.List.Tot

let rec lookup (l:list (string & sterm)) (x:string) : Tot sterm (decreases l) =
  match l with
  | [] -> initial
  | (y, t) :: r -> if y = x then t else lookup r x

let rec lookup_message (l:list (string & sterm)) (x:string)
  : Lemma (requires L.for_all (fun (p:string & sterm) -> message (snd p)) l)
          (ensures message (lookup l x) = true) (decreases l)
  = match l with
    | [] -> ()
    | (y, t) :: r -> if y = x then () else lookup_message r x

let mk_sg (l:list (string & sterm)) : subst = lookup l

let mk_sg_message (l:list (string & sterm))
  : Lemma (requires L.for_all (fun (p:string & sterm) -> message (snd p)) l)
          (ensures message_subst (mk_sg l))
  = introduce forall (x:string). message (mk_sg l x) = true
    with lookup_message l x

let mk_nu (l:list (string & string)) : fresh_subst =
  fun x -> match L.assoc x l with Some n -> n | None -> "unused"

let sS : sterm = SName (FreshName "s")
let sI : sterm = SName (FreshName "i")
let sT1 : sterm = SName (FreshName "t1")
let sT2 : sterm = SName (FreshName "t2")
let g1 : sterm = successor initial
let g2 : sterm = successor (successor initial)
let n1 : sterm = successor initial
let n2 : sterm = successor (successor initial)
let p1 : sterm = public_name "p1"
let p2 : sterm = public_name "p2"

let nu0 : fresh_subst = mk_nu [("slot", "s"); ("item", "i"); ("tx", "t1")]
let nu1 : fresh_subst = mk_nu [("tx", "t2")]

let fresh_cfg (c:config) (n:string) : config =
  { c with facts = fr_fact n :: c.facts; drawn = n :: c.drawn }
let send_cfg (c:config) (t:sterm) : config =
  { c with facts = in_fact t :: c.facts }

let c0 : config = init_config
let c1 : config = fresh_cfg c0 "s"
let c2 : config = fresh_cfg c1 "i"
let all_msg (l:list (string & sterm)) : bool =
  L.for_all (fun (p:string & sterm) -> message (snd p)) l

let rstep (c:config) (r:rule_name) (l:list (string & sterm)) (nu:fresh_subst)
    (_:squash (all_msg l = true))
    (_:squash (rule_enabled Original c r (mk_sg l) nu = true))
  : sstep Original c (LRule r (mk_sg l) nu) (rule_result Original c r (mk_sg l) nu)
  = mk_sg_message l;
    SRule c r (mk_sg l) nu () ()

let fstep (c:config) (n:string) (_:squash (L.mem n c.drawn = false))
  : sstep Original c (LFresh n) (fresh_cfg c n)
  = SFresh c n ()

let d_pair (k:list sterm) (a b:sterm) (da:derivable k a) (db:derivable k b)
  : derivable k (SPair a b) = DPair a b da db

let d_init (k:list sterm) : derivable k initial = DPublic "initial"

let d_succ (k:list sterm) (a:sterm) (da:derivable k a)
    (_:squash (message (successor a) = true))
  : derivable k (successor a) = DApp Successor a da ()

let d_n1 (k:list sterm) : derivable k n1 = d_succ k initial (d_init k) ()
let d_n2 (k:list sterm) : derivable k n2 = d_succ k n1 (d_n1 k) ()

let l_init : list (string & sterm) = []
let l_read1 : list (string & sterm) = [("slot", sS); ("gen", initial); ("pinned", initial)]
let l_pj1 : list (string & sterm) =
  [("slot", sS); ("gen", initial); ("pinned", initial); ("vrev", initial);
   ("vpayload", sI); ("tx", sT1); ("next_revision", n1); ("payload", p1)]
let l_crash : list (string & sterm) = [("slot", sS)]
let l_pv1 : list (string & sterm) =
  [("slot", sS); ("tx", sT1); ("gen", g1); ("next", n1); ("payload", p1);
   ("vrev", initial); ("vpayload", sI)]
let l_cj1 : list (string & sterm) =
  [("slot", sS); ("tx", sT1); ("gen", g1); ("pinned", n1); ("intended", p1);
   ("vrev", n1); ("vpayload", p1)]
let l_ov : list (string & sterm) =
  [("slot", sS); ("gen", g1); ("pinned", n1); ("revision", n1); ("payload", p1)]
let l_read2 : list (string & sterm) = [("slot", sS); ("gen", g1); ("pinned", n1)]
let l_pj2 : list (string & sterm) =
  [("slot", sS); ("gen", g1); ("pinned", n1); ("vrev", n1); ("vpayload", p1);
   ("tx", sT2); ("next_revision", n2); ("payload", p2)]
let l_pv2 : list (string & sterm) =
  [("slot", sS); ("tx", sT2); ("gen", g2); ("next", n2); ("payload", p2);
   ("vrev", n1); ("vpayload", p1)]
let l_cj2 : list (string & sterm) =
  [("slot", sS); ("tx", sT2); ("gen", g2); ("pinned", n2); ("intended", p2);
   ("vrev", n2); ("vpayload", p2)]

let lb (r:rule_name) (l:list (string & sterm)) (nu:fresh_subst) : label =
  LRule r (mk_sg l) nu

let h1 : strace = TSnoc TNil (LFresh "s")
let h2 : strace = TSnoc h1 (LFresh "i")
let h3 : strace = TSnoc h2 (lb R_Initialize l_init nu0)
let h4 : strace = TSnoc h3 (LFresh "t1")
let h5 : strace = TSnoc h4 (lb R_ReadSnapshot l_read1 nu0)
let h6 : strace = TSnoc h5 (LSend (SPair n1 p1))
let h7 : strace = TSnoc h6 (lb R_PersistJournal l_pj1 nu0)
let h8 : strace = TSnoc h7 (lb R_Crash l_crash nu0)
let h9 : strace = TSnoc h8 (lb R_PersistVault l_pv1 nu0)
let h10 : strace = TSnoc h9 (lb R_ClearJournal l_cj1 nu0)
let h11 : strace = TSnoc h10 (lb R_OpenVault l_ov nu0)
let h12 : strace = TSnoc h11 (LFresh "t2")
let h13 : strace = TSnoc h12 (lb R_ReadSnapshot l_read2 nu1)
let h14 : strace = TSnoc h13 (LSend (SPair n2 p2))
let h15 : strace = TSnoc h14 (lb R_PersistJournal l_pj2 nu1)
let h16 : strace = TSnoc h15 (lb R_PersistVault l_pv2 nu1)
let h17 : strace = TSnoc h16 (lb R_ClearJournal l_cj2 nu1)

let k1 : config = rule_result Original c2 R_Initialize (mk_sg l_init) nu0
let k2 : config = fresh_cfg k1 "t1"
let k3 : config = rule_result Original k2 R_ReadSnapshot (mk_sg l_read1) nu0
let k4 : config = send_cfg k3 (SPair n1 p1)
let k5 : config = rule_result Original k4 R_PersistJournal (mk_sg l_pj1) nu0
let k6 : config = rule_result Original k5 R_Crash (mk_sg l_crash) nu0
let k7 : config = rule_result Original k6 R_PersistVault (mk_sg l_pv1) nu0
let k8 : config = rule_result Original k7 R_ClearJournal (mk_sg l_cj1) nu0
let k9 : config = rule_result Original k8 R_OpenVault (mk_sg l_ov) nu0
let k10 : config = fresh_cfg k9 "t2"
let k11 : config = rule_result Original k10 R_ReadSnapshot (mk_sg l_read2) nu1
let k12 : config = send_cfg k11 (SPair n2 p2)
let k13 : config = rule_result Original k12 R_PersistJournal (mk_sg l_pj2) nu1
let k14 : config = rule_result Original k13 R_PersistVault (mk_sg l_pv2) nu1
let k15 : config = rule_result Original k14 R_ClearJournal (mk_sg l_cj2) nu1

let r1 : sreach Original h1 c1 = SRStep TNil c0 (LFresh "s") c1 SRInit (fstep c0 "s" ())
let r2 : sreach Original h2 c2 = SRStep h1 c1 (LFresh "i") c2 r1 (fstep c1 "i" ())

let r3 : sreach Original h3 k1 =
  assert_norm (rule_enabled Original c2 R_Initialize (mk_sg l_init) nu0 = true);
  SRStep h2 c2 _ k1 r2 (rstep c2 R_Initialize l_init nu0 () ())

let r4 : sreach Original h4 k2 =
  assert_norm (L.mem "t1" k1.drawn = false);
  SRStep h3 k1 (LFresh "t1") k2 r3 (fstep k1 "t1" ())

let r5 : sreach Original h5 k3 =
  assert_norm (all_msg l_read1 = true);
  assert_norm (rule_enabled Original k2 R_ReadSnapshot (mk_sg l_read1) nu0 = true);
  SRStep h4 k2 _ k3 r4 (rstep k2 R_ReadSnapshot l_read1 nu0 () ())

let r6 : sreach Original h6 k4 =
  let d = d_pair k3.know n1 p1 (d_n1 k3.know) (DPublic "p1") in
  SRStep h5 k3 (LSend (SPair n1 p1)) k4 r5 (SSend k3 (SPair n1 p1) d)

let r7 : sreach Original h7 k5 =
  assert_norm (all_msg l_pj1 = true);
  assert_norm (rule_enabled Original k4 R_PersistJournal (mk_sg l_pj1) nu0 = true);
  SRStep h6 k4 _ k5 r6 (rstep k4 R_PersistJournal l_pj1 nu0 () ())

let r8 : sreach Original h8 k6 =
  assert_norm (all_msg l_crash = true);
  assert_norm (rule_enabled Original k5 R_Crash (mk_sg l_crash) nu0 = true);
  SRStep h7 k5 _ k6 r7 (rstep k5 R_Crash l_crash nu0 () ())

let r9 : sreach Original h9 k7 =
  assert_norm (all_msg l_pv1 = true);
  assert_norm (rule_enabled Original k6 R_PersistVault (mk_sg l_pv1) nu0 = true);
  SRStep h8 k6 _ k7 r8 (rstep k6 R_PersistVault l_pv1 nu0 () ())

let r10 : sreach Original h10 k8 =
  assert_norm (all_msg l_cj1 = true);
  assert_norm (rule_enabled Original k7 R_ClearJournal (mk_sg l_cj1) nu0 = true);
  SRStep h9 k7 _ k8 r9 (rstep k7 R_ClearJournal l_cj1 nu0 () ())

let r11 : sreach Original h11 k9 =
  assert_norm (all_msg l_ov = true);
  assert_norm (rule_enabled Original k8 R_OpenVault (mk_sg l_ov) nu0 = true);
  SRStep h10 k8 _ k9 r10 (rstep k8 R_OpenVault l_ov nu0 () ())

let r12 : sreach Original h12 k10 =
  assert_norm (L.mem "t2" k9.drawn = false);
  SRStep h11 k9 (LFresh "t2") k10 r11 (fstep k9 "t2" ())

let r13 : sreach Original h13 k11 =
  assert_norm (all_msg l_read2 = true);
  assert_norm (rule_enabled Original k10 R_ReadSnapshot (mk_sg l_read2) nu1 = true);
  SRStep h12 k10 _ k11 r12 (rstep k10 R_ReadSnapshot l_read2 nu1 () ())

let r14 : sreach Original h14 k12 =
  let d = d_pair k11.know n2 p2 (d_n2 k11.know) (DPublic "p2") in
  SRStep h13 k11 (LSend (SPair n2 p2)) k12 r13 (SSend k11 (SPair n2 p2) d)

let r15 : sreach Original h15 k13 =
  assert_norm (all_msg l_pj2 = true);
  assert_norm (rule_enabled Original k12 R_PersistJournal (mk_sg l_pj2) nu1 = true);
  SRStep h14 k12 _ k13 r14 (rstep k12 R_PersistJournal l_pj2 nu1 () ())

let r16 : sreach Original h16 k14 =
  assert_norm (all_msg l_pv2 = true);
  assert_norm (rule_enabled Original k13 R_PersistVault (mk_sg l_pv2) nu1 = true);
  SRStep h15 k13 _ k14 r15 (rstep k13 R_PersistVault l_pv2 nu1 () ())

(* The whole witness trace in the original source system. *)
let witness_reach : sreach Original h17 k15 =
  assert_norm (all_msg l_cj2 = true);
  assert_norm (rule_enabled Original k14 R_ClearJournal (mk_sg l_cj2) nu1 = true);
  SRStep h16 k14 _ k15 r16 (rstep k14 R_ClearJournal l_cj2 nu1 () ())

(* #17: the attacker receives Out(~s); it then knows the slot name. *)
let rest16 : list fact =
  match remove1 (out_fact sS) k15.facts with Some r -> r | None -> []
let k16 : config = { k15 with facts = rest16; know = sS :: k15.know }
let h18 : strace = TSnoc h17 (LRecv sS)

let r18 : sreach Original h18 k16 =
  assert_norm (remove1 (out_fact sS) k15.facts == Some rest16);
  SRStep h17 k15 (LRecv sS) k16 witness_reach (SRecv k15 sS rest16 ())

(* The restriction holds on the witness. *)
let increasing_snoc (h:strace) (l:label)
  : Lemma (requires increasing h
                    /\ (forall (o n:sterm). L.mem (a_revision_increases o n) (actions l) = true
                                          ==> proper_subterm o n = true))
          (ensures increasing (TSnoc h l))
  = introduce forall (i:nat) (o n:sterm).
      action_at (TSnoc h l) i (a_revision_increases o n) = true ==> proper_subterm o n = true
    with introduce _ ==> _
    with _. begin
      if i = slen h then
        assert (L.mem (a_revision_increases o n) (actions l) = true)
      else
        assert (action_at h i (a_revision_increases o n) = true)
    end

let no_increase (l:label) : Type0 =
  has_sym F_RevisionIncreases (actions l) = false

let no_increase_ok (h:strace) (l:label)
  : Lemma (requires increasing h /\ no_increase l) (ensures increasing (TSnoc h l))
  = introduce forall (o n:sterm).
      L.mem (a_revision_increases o n) (actions l) = true ==> proper_subterm o n = true
    with introduce _ ==> _
    with _. begin
      no_sym_cnt (a_revision_increases o n) (actions l);
      mem_cnt (a_revision_increases o n) (actions l)
    end;
    increasing_snoc h l

let journal_increase_ok (h:strace) (l:label) (o n:sterm) (x:fact)
  : Lemma (requires increasing h /\ actions l == [a_revision_increases o n; x]
                    /\ x.f_sym = F_JournalDurable /\ proper_subterm o n = true)
          (ensures increasing (TSnoc h l))
  = increasing_snoc h l

let witness_increasing () : Lemma (increasing h18) =
  assert_norm (no_increase (LFresh "s"));
  no_increase_ok TNil (LFresh "s");
  no_increase_ok h1 (LFresh "i");
  assert_norm (no_increase (lb R_Initialize l_init nu0));
  no_increase_ok h2 (lb R_Initialize l_init nu0);
  no_increase_ok h3 (LFresh "t1");
  assert_norm (no_increase (lb R_ReadSnapshot l_read1 nu0));
  no_increase_ok h4 (lb R_ReadSnapshot l_read1 nu0);
  no_increase_ok h5 (LSend (SPair n1 p1));
  assert_norm (actions (lb R_PersistJournal l_pj1 nu0)
               == [a_revision_increases initial n1;
                   a_journal_durable sS sT1 g1 initial n1 p1]);
  assert_norm (proper_subterm initial n1 = true);
  journal_increase_ok h6 (lb R_PersistJournal l_pj1 nu0) initial n1
    (a_journal_durable sS sT1 g1 initial n1 p1);
  assert_norm (no_increase (lb R_Crash l_crash nu0));
  no_increase_ok h7 (lb R_Crash l_crash nu0);
  assert_norm (no_increase (lb R_PersistVault l_pv1 nu0));
  no_increase_ok h8 (lb R_PersistVault l_pv1 nu0);
  assert_norm (no_increase (lb R_ClearJournal l_cj1 nu0));
  no_increase_ok h9 (lb R_ClearJournal l_cj1 nu0);
  assert_norm (no_increase (lb R_OpenVault l_ov nu0));
  no_increase_ok h10 (lb R_OpenVault l_ov nu0);
  no_increase_ok h11 (LFresh "t2");
  assert_norm (no_increase (lb R_ReadSnapshot l_read2 nu1));
  no_increase_ok h12 (lb R_ReadSnapshot l_read2 nu1);
  no_increase_ok h13 (LSend (SPair n2 p2));
  assert_norm (actions (lb R_PersistJournal l_pj2 nu1)
               == [a_revision_increases n1 n2;
                   a_journal_durable sS sT2 g2 n1 n2 p2]);
  assert_norm (proper_subterm n1 n2 = true);
  journal_increase_ok h14 (lb R_PersistJournal l_pj2 nu1) n1 n2
    (a_journal_durable sS sT2 g2 n1 n2 p2);
  assert_norm (no_increase (lb R_PersistVault l_pv2 nu1));
  no_increase_ok h15 (lb R_PersistVault l_pv2 nu1);
  assert_norm (no_increase (lb R_ClearJournal l_cj2 nu1));
  no_increase_ok h16 (lb R_ClearJournal l_cj2 nu1);
  no_increase_ok h17 (LRecv sS)

(* exists-trace lemma recovery_is_reachable, on the source witness. *)
let witness_recovery () : Lemma (recovery_is_reachable h18) =
  assert_norm (action_at h18 6 (a_journal_durable sS sT1 g1 initial n1 p1) = true);
  assert_norm (action_at h18 7 (a_crash sS) = true);
  assert_norm (action_at h18 8 (a_vault_durable sS sT1 g1 n1 p1) = true);
  assert_norm (action_at h18 9 (a_journal_cleared sS sT1 g1 n1) = true);
  assert_norm (action_at h18 10 (a_opened sS g1 n1 n1 p1) = true)

(* exists-trace lemma two_successive_commits_advance, on the same trace. *)
let witness_two_commits () : Lemma (two_successive_commits_advance h18) =
  assert_norm (action_at h18 6 (a_journal_durable sS sT1 (successor initial) initial n1 p1) = true);
  assert_norm (action_at h18 9 (a_journal_cleared sS sT1 (successor initial) n1) = true);
  assert_norm (action_at h18 14
                 (a_journal_durable sS sT2 (successor (successor initial)) n1 n2 p2) = true);
  assert_norm (action_at h18 16
                 (a_journal_cleared sS sT2 (successor (successor initial)) n2) = true);
  assert_norm (proper_subterm n1 n2 = true)

(* The same trace is admitted by the Chain-instrumented system. *)
let witness_instrumented : (ci:config & sreach Instrumented h18 ci) =
  let (| ci, r |) = lift_source h18 k16 r18 in (| ci, r |)

(* The attacker's knowledge is real: after receiving Out(~s) it knows the
   slot, but the initial vault item ~i was never sent and is not derivable,
   so it can never be supplied as a payload. *)
let witness_item_secret (t:sterm) (d:derivable k16.know t)
  : Lemma (requires occurs_fresh "i" t = true) (ensures False)
  = assert_norm (k16.know == [sS]);
    assert_norm (known_fresh "i" [sS] = false);
    fresh_name_secret k16.know "i" t d

let witness_slot_known : derivable k16.know sS =
  assert_norm (L.mem sS k16.know = true);
  DKnown sS ()

(* Both exists-trace lemmas, on one restricted trace of each system. *)
let m28_exists (h:strace) : Type0 =
  recovery_is_reachable h /\ two_successive_commits_advance h

let original_exists_lemmas : holds_for_some Original m28_exists =
  witness_increasing ();
  witness_recovery ();
  witness_two_commits ();
  Witness h18 k16 r18 ()

let instrumented_exists_lemmas : holds_for_some Instrumented m28_exists =
  witness_original_to_instrumented m28_exists original_exists_lemmas
