package txn

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TheDirepack/Nix-nas/go/internal/syspath"
)

// fakeFS acts on a real temporary tree with fault injection, standing in
// for the privileged coreutils of production.
type fakeFS struct {
	moves     int
	failMove  int
	failRm    func(p string) bool
	realpathE func(p string) error
}

func (f *fakeFS) stat(p syspath.Abs) (os.FileInfo, error) { return os.Stat(p.String()) }
func (f *fakeFS) IsDir(_ context.Context, p syspath.Abs) bool {
	st, err := f.stat(p)
	return err == nil && st.IsDir()
}
func (f *fakeFS) IsFile(_ context.Context, p syspath.Abs) bool {
	st, err := f.stat(p)
	return err == nil && st.Mode().IsRegular()
}
func (f *fakeFS) IsSymlink(_ context.Context, p syspath.Abs) bool {
	st, err := os.Lstat(p.String())
	return err == nil && st.Mode()&os.ModeSymlink != 0
}
func (f *fakeFS) Exists(_ context.Context, p syspath.Abs) bool {
	_, err := f.stat(p)
	return err == nil
}
func (f *fakeFS) Realpath(_ context.Context, p syspath.Abs) (string, error) {
	if f.realpathE != nil {
		if err := f.realpathE(p.String()); err != nil {
			return "", err
		}
	}
	return filepath.EvalSymlinks(p.String())
}
func (f *fakeFS) Move(_ context.Context, src, dst syspath.Abs) error {
	f.moves++
	if f.moves == f.failMove {
		return &StepError{Argv: []string{"mv"}, Code: 74}
	}
	return os.Rename(src.String(), dst.String())
}
func (f *fakeFS) RemoveAll(_ context.Context, p syspath.Abs) error {
	if f.failRm != nil && f.failRm(p.String()) {
		return &StepError{Argv: []string{"rm"}, Code: 74}
	}
	return os.RemoveAll(p.String())
}

// fakeSystemd models systemctl show/stop/start.
type fakeSystemd struct {
	log         []string
	unavailable bool
	showFail    bool
	load        string
	state       string // forced ActiveState when set
	active      bool
	job         string
	jobMissing  bool
	stopFail    bool
	stopLeaves  bool // a failed stop still left the target inactive
	startFail   bool
	onStop      func(*fakeSystemd)
}

func newSystemd() *fakeSystemd { return &fakeSystemd{load: "loaded", active: true} }

func (s *fakeSystemd) Show(_ context.Context, t syspath.Target) (string, error) {
	s.log = append(s.log, "show "+t.String())
	if s.unavailable || s.showFail {
		return "", errors.New("Failed to query status")
	}
	out := "LoadState=" + s.load + "\n"
	if !s.jobMissing {
		out += "Job=" + s.job + "\n"
	}
	switch {
	case s.state != "":
		out += "ActiveState=" + s.state + "\n"
	case s.active:
		out += "ActiveState=active\n"
	default:
		out += "ActiveState=inactive\n"
	}
	return out, nil
}

func (s *fakeSystemd) Stop(_ context.Context, t syspath.Target) error {
	s.log = append(s.log, "stop "+t.String())
	if s.unavailable {
		return errors.New("bus")
	}
	if s.onStop != nil {
		s.onStop(s)
	}
	if s.stopFail {
		if s.stopLeaves {
			s.active = false
		}
		return errors.New("stop failed")
	}
	s.active = false
	return nil
}

func (s *fakeSystemd) Start(_ context.Context, t syspath.Target) error {
	s.log = append(s.log, "start "+t.String())
	if s.startFail || s.unavailable {
		return errors.New("start failed")
	}
	s.active = true
	return nil
}

func (s *fakeSystemd) started() bool {
	for _, l := range s.log {
		if strings.HasPrefix(l, "start ") {
			return true
		}
	}
	return false
}

type world struct {
	t      *testing.T
	dir    string
	fs     *fakeFS
	sd     *fakeSystemd
	log    bytes.Buffer
	target syspath.Target
}

func newWorld(t *testing.T) *world {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w := &world{t: t, dir: dir, fs: &fakeFS{}, sd: newSystemd()}
	w.target, _ = NewTarget("nas-protected-services.target")
	for _, p := range []string{"root/ready", "root/old", "stage/ready", "stage/new"} {
		w.touch(p)
	}
	return w
}

// NewTarget is a test shorthand.
func NewTarget(s string) (syspath.Target, error) { return syspath.NewTarget(s) }

func (w *world) p(rel string) syspath.Abs { return syspath.MustAbs(filepath.Join(w.dir, rel)) }
func (w *world) touch(rel string) {
	full := filepath.Join(w.dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(full, nil, 0o600); err != nil {
		w.t.Fatal(err)
	}
}
func (w *world) exists(rel string) bool {
	_, err := os.Lstat(filepath.Join(w.dir, rel))
	return err == nil
}
func (w *world) must(rels ...string) {
	w.t.Helper()
	for _, r := range rels {
		if strings.HasPrefix(r, "!") {
			if w.exists(r[1:]) {
				w.t.Fatalf("%s must not exist", r[1:])
			}
		} else if !w.exists(r) {
			w.t.Fatalf("%s must exist", r)
		}
	}
}

func (w *world) plan(stage, previous string, dir *string) (Plan, error) {
	var d *syspath.Abs
	if dir != nil {
		v := w.p(*dir)
		d = &v
	}
	return NewPlan(w.p("root"), w.p(stage), w.p(previous), d, w.target)
}

func (w *world) begin(stage, previous string, dir *string) *Staged {
	w.t.Helper()
	plan, err := w.plan(stage, previous, dir)
	if err != nil {
		w.t.Fatal(err)
	}
	s, err := Begin(context.Background(), w.fs, w.sd, &w.log, plan)
	if err != nil {
		w.t.Fatal(err)
	}
	return s
}

func (w *world) simple() *Staged { return w.begin("stage", "previous", nil) }

func (w *world) withTx() *Staged {
	if err := os.Rename(filepath.Join(w.dir, "stage"), filepath.Join(w.dir, "tx-new")); err != nil {
		w.t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(w.dir, "tx"), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(w.dir, "tx-new"), filepath.Join(w.dir, "tx/new")); err != nil {
		w.t.Fatal(err)
	}
	dir := "tx"
	return w.begin("tx/new", "tx/previous", &dir)
}

func (w *world) logged(s string) bool { return strings.Contains(w.log.String(), s) }

func TestUnstableInitialObservationPreservesBothTrees(t *testing.T) {
	for name, set := range map[string]func(*fakeSystemd){
		"unavailable":   func(s *fakeSystemd) { s.unavailable = true },
		"show fails":    func(s *fakeSystemd) { s.showFail = true },
		"activating":    func(s *fakeSystemd) { s.state = "activating" },
		"deactivating":  func(s *fakeSystemd) { s.state = "deactivating" },
		"reloading":     func(s *fakeSystemd) { s.state = "reloading" },
		"unknown":       func(s *fakeSystemd) { s.state = "unknown" },
		"not found":     func(s *fakeSystemd) { s.load = "not-found" },
		"queued job":    func(s *fakeSystemd) { s.state, s.job = "inactive", "42" },
		"job prop gone": func(s *fakeSystemd) { s.jobMissing = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			set(w.sd)
			s := w.simple()
			if _, err := s.Swap(context.Background()); err == nil {
				t.Fatal("swap must fail")
			}
			w.must("root/old", "stage/new", "!previous")
			r := s.Abort(9)
			if r.Status != ExitManualRecovery || r.Complete {
				t.Fatalf("got %+v", r)
			}
			w.must("root/old", "stage/new", "!previous")
			if w.fs.moves != 0 || w.sd.started() || !w.logged("primary status 9") {
				t.Fatalf("moves=%d log=%v\n%s", w.fs.moves, w.sd.log, w.log.String())
			}
		})
	}
}

func TestStopMustBeObservedStable(t *testing.T) {
	for name, after := range map[string]func(*fakeSystemd){
		"show fails":   func(s *fakeSystemd) { s.showFail = true },
		"activating":   func(s *fakeSystemd) { s.state = "activating" },
		"deactivating": func(s *fakeSystemd) { s.state = "deactivating" },
		"still active": func(s *fakeSystemd) { s.state = "active" },
		"queued job":   func(s *fakeSystemd) { s.state, s.job = "inactive", "42" },
		"job missing":  func(s *fakeSystemd) { s.jobMissing = true },
	} {
		for _, stopFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stopfail=%v", name, stopFails), func(t *testing.T) {
				w := newWorld(t)
				w.sd.stopFail = stopFails
				w.sd.onStop = after
				s := w.simple()
				if _, err := s.Swap(context.Background()); err == nil {
					t.Fatal("swap must fail")
				}
				w.must("root/old", "stage/new", "!previous")
				if r := s.Abort(83); r.Status != ExitManualRecovery {
					t.Fatalf("got %+v", r)
				}
				w.must("root/old", "stage/new", "!previous")
				if w.fs.moves != 0 {
					t.Fatal("no tree may move")
				}
			})
		}
	}
}

func TestInactiveOrFailedTargetSwapsWithoutRestartOnRollback(t *testing.T) {
	for _, state := range []string{"inactive", "failed"} {
		w := newWorld(t)
		w.sd.state, w.sd.active, w.sd.stopFail = state, false, true
		s := w.simple()
		sw, err := s.Swap(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		w.must("root/new", "previous/old")
		if r := sw.Abort(79); r.Status != 79 || !r.Complete {
			t.Fatalf("%s: %+v", state, r)
		}
		w.must("root/old", "!previous")
		if w.sd.started() {
			t.Fatal("an inactive target must stay stopped")
		}
	}
}

func TestRollbackStopFailurePreservesAllMaterial(t *testing.T) {
	for name, set := range map[string]func(*fakeSystemd){
		"unavailable": func(s *fakeSystemd) { s.unavailable = true },
		"show fails":  func(s *fakeSystemd) { s.showFail = true },
		"activating":  func(s *fakeSystemd) { s.state = "activating" },
		"active":      func(s *fakeSystemd) { s.state = "active" },
		"queued job":  func(s *fakeSystemd) { s.state, s.job = "inactive", "42" },
		"job missing": func(s *fakeSystemd) { s.jobMissing = true },
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			sw, err := w.withTx().Swap(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			w.touch("tx/new/partial")
			w.sd.stopFail = true
			set(w.sd)
			r := sw.Abort(71)
			if r.Status != ExitManualRecovery || sw.Phase() != PhaseRollbackIncomplete {
				t.Fatalf("got %+v phase %v", r, sw.Phase())
			}
			w.must("root/new", "root/ready", "tx/previous/old", "tx/previous/ready", "tx/new/partial")
			if w.fs.moves != 2 || !w.logged(w.p("tx/previous").String()) || !w.logged(w.p("tx/new").String()) ||
				!w.logged("primary status 71") || w.sd.started() {
				t.Fatalf("moves=%d\n%s", w.fs.moves, w.log.String())
			}
		})
	}
}

func TestRollbackRestoresPreviousTreeAndRestarts(t *testing.T) {
	w := newWorld(t)
	sw, err := w.simple().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := sw.Abort(71); r.Status != 71 || !r.Complete {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "!root/new")
	if w.sd.log[len(w.sd.log)-1] != "start nas-protected-services.target" {
		t.Fatalf("log %v", w.sd.log)
	}
}

func TestPreSwapFailureDoesNotTouchTarget(t *testing.T) {
	w := newWorld(t)
	if r := w.simple().Abort(77); r.Status != 77 {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "root/ready")
	if len(w.sd.log) != 0 {
		t.Fatalf("systemd touched: %v", w.sd.log)
	}
}

func TestFailedPreSwapCleanupReportsRetainedTrees(t *testing.T) {
	w := newWorld(t)
	s := w.withTx()
	stage := w.p("tx/new").String()
	w.fs.failRm = func(p string) bool { return p == stage }
	r := s.Abort(78)
	if r.Status != ExitManualRecovery || s.c.phase != PhaseRollbackIncomplete {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "root/ready", "tx/new/new")
	want := fmt.Sprintf("nas-secret-transaction: pre-swap cleanup was incomplete; retained recovery tree %s; staged tree %s\n", w.p("tx"), stage)
	if !w.logged(want) || len(w.sd.log) != 0 {
		t.Fatalf("log:\n%s", w.log.String())
	}
}

func TestFailedRestartReportsIncompleteRollback(t *testing.T) {
	w := newWorld(t)
	w.sd.startFail = true
	sw, err := w.simple().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := sw.Abort(78); r.Status != ExitManualRecovery {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "!root/new")
}

func TestCommitRemovesPreviousAndTransactionDirectory(t *testing.T) {
	w := newWorld(t)
	sw, err := w.withTx().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done, cerr := sw.Commit(context.Background())
	if cerr != nil || done.Phase() != PhaseCommitted {
		t.Fatalf("%v %v", cerr, done.Phase())
	}
	w.must("root/new", "!root/old", "!tx")
}

func TestCommitCleanupFailureKeepsNewTreeAuthoritative(t *testing.T) {
	w := newWorld(t)
	sw, err := w.simple().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prev := w.p("previous").String()
	w.fs.failRm = func(p string) bool { return p == prev }
	done, cerr := sw.Commit(context.Background())
	if cerr == nil || done.Phase() != PhaseCommitCleanupFailed {
		t.Fatal("cleanup failure must be reported")
	}
	w.must("root/new")
}

func TestConsumedStatesPanic(t *testing.T) {
	w := newWorld(t)
	s := w.simple()
	sw, err := s.Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for name, misuse := range map[string]func(){
		"swap staged twice":  func() { _, _ = s.Swap(context.Background()) },
		"abort staged after": func() { s.Abort(1) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s must panic", name)
				}
			}()
			misuse()
		}()
	}
	if _, cerr := sw.Commit(context.Background()); cerr != nil {
		t.Fatal(cerr)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("abort after commit must panic")
		}
	}()
	sw.Abort(1)
}

func TestSecondSwapAfterFailureIsRejectedAndRollbackRestores(t *testing.T) {
	w := newWorld(t)
	w.fs.failMove = 2
	s := w.simple()
	if _, err := s.Swap(context.Background()); err == nil {
		t.Fatal("swap must fail at the second move")
	}
	if _, err := s.Swap(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid swap phase") {
		t.Fatalf("second swap: %v", err)
	}
	if r := s.Abort(79); r.Status != 79 {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "!root/new", "!previous")
}

func TestMissingPreviousTreeIsManualRecovery(t *testing.T) {
	w := newWorld(t)
	sw, err := w.simple().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = os.RemoveAll(filepath.Join(w.dir, "previous"))
	if r := sw.Abort(80); r.Status != ExitManualRecovery {
		t.Fatalf("%+v", r)
	}
	w.must("!root/new")
	if w.sd.started() {
		t.Fatal("must not restart without a restored tree")
	}
}

func TestMissingReadyMarkerPreventsRestart(t *testing.T) {
	w := newWorld(t)
	sw, err := w.simple().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(w.dir, "previous/ready"))
	if r := sw.Abort(81); r.Status != ExitManualRecovery {
		t.Fatalf("%+v", r)
	}
	w.must("root/old")
	if w.sd.started() {
		t.Fatal("must not restart an unready tree")
	}
}

func TestSymlinkedStageOrLiveRootRejectedBeforeStop(t *testing.T) {
	for _, which := range []string{"stage", "root"} {
		w := newWorld(t)
		w.touch("outside/ready")
		_ = os.RemoveAll(filepath.Join(w.dir, which))
		if err := os.Symlink(filepath.Join(w.dir, "outside"), filepath.Join(w.dir, which)); err != nil {
			t.Fatal(err)
		}
		if _, err := w.simple().Swap(context.Background()); err == nil {
			t.Fatalf("symlinked %s must be rejected", which)
		}
		if len(w.sd.log) != 0 {
			t.Fatalf("systemd touched: %v", w.sd.log)
		}
	}
}

func TestSymlinkedParentsAndTransactionDirectoryRejected(t *testing.T) {
	w := newWorld(t)
	w.touch("real/new/ready")
	if err := os.Symlink(filepath.Join(w.dir, "real"), filepath.Join(w.dir, "linked")); err != nil {
		t.Fatal(err)
	}
	plan, err := w.plan("linked/new", "linked/previous", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Begin(context.Background(), w.fs, w.sd, &w.log, plan); err == nil {
		t.Fatal("symlinked parent must be rejected")
	}
	dir := "linked"
	plan, err = w.plan("linked/new", "linked/previous", &dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Begin(context.Background(), w.fs, w.sd, &w.log, plan); err == nil {
		t.Fatal("symlinked transaction directory must be rejected")
	}
	if len(w.sd.log) != 0 {
		t.Fatal("systemd touched")
	}
}

func TestPrivilegedResolutionFailureRejectsTransactionDirectory(t *testing.T) {
	w := newWorld(t)
	w.touch("tx/transaction.1/new/ready")
	w.fs.realpathE = func(string) error { return errors.New("permission denied") }
	dir := "tx/transaction.1"
	plan, err := w.plan("tx/transaction.1/new", "tx/transaction.1/previous", &dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Begin(context.Background(), w.fs, w.sd, &w.log, plan); err == nil {
		t.Fatal("an unresolvable layout must be rejected")
	}
}

func TestMissingStageAndPreexistingPreviousRejectedBeforeStop(t *testing.T) {
	w := newWorld(t)
	_ = os.RemoveAll(filepath.Join(w.dir, "stage"))
	if _, err := w.simple().Swap(context.Background()); err == nil {
		t.Fatal("missing stage must be rejected")
	}
	w2 := newWorld(t)
	w2.touch("previous/stale")
	if _, err := w2.simple().Swap(context.Background()); err == nil {
		t.Fatal("existing previous must be rejected")
	}
	w2.must("root/old", "stage/new", "previous/stale")
	if len(w.sd.log)+len(w2.sd.log) != 0 {
		t.Fatal("systemd touched")
	}
}

func TestPlanRequiresAbsoluteDisjointPaths(t *testing.T) {
	w := newWorld(t)
	target := w.target
	cases := [][3]syspath.Abs{
		{w.p("root"), w.p("root/child"), w.p("previous")},
		{w.p("root"), w.p("stage"), w.p("stage/previous")},
		{syspath.MustAbs("/"), w.p("stage"), w.p("previous")},
		{{}, w.p("stage"), w.p("previous")},
	}
	for _, c := range cases {
		if _, err := NewPlan(c[0], c[1], c[2], nil, target); err == nil {
			t.Errorf("accepted %v", c)
		}
	}
	inside := w.p("root/tx")
	if _, err := NewPlan(w.p("root"), w.p("tx/new"), w.p("tx/previous"), &inside, target); err == nil {
		t.Error("transaction directory inside the live root must be rejected")
	}
	other := w.p("elsewhere")
	if _, err := NewPlan(w.p("root"), w.p("tx/new"), w.p("tx/previous"), &other, target); err == nil {
		t.Error("stage outside the transaction directory must be rejected")
	}
	for _, bad := range []string{"--root=/tmp.target", "bad.service", "bad.target\nnext"} {
		if _, err := syspath.NewTarget(bad); err == nil {
			t.Errorf("accepted target %q", bad)
		}
	}
}

func TestInactiveSystemWithoutPriorRootRollsBackToNoRoot(t *testing.T) {
	w := newWorld(t)
	w.sd.active = false
	_ = os.RemoveAll(filepath.Join(w.dir, "root"))
	sw, err := w.simple().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := sw.Abort(82); r.Status != 82 {
		t.Fatalf("%+v", r)
	}
	w.must("!root", "!previous")
	if w.sd.started() {
		t.Fatal("must stay stopped")
	}
}

func TestStopFailureAbortsWithoutSwappingFiles(t *testing.T) {
	w := newWorld(t)
	w.sd.stopFail = true
	s := w.simple()
	if _, err := s.Swap(context.Background()); err == nil {
		t.Fatal("swap must fail")
	}
	if r := s.Abort(83); r.Status != ExitManualRecovery {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "!root/new", "!previous")
}

func TestNonzeroStopAcceptedOnlyWhenTargetBecameInactive(t *testing.T) {
	w := newWorld(t)
	w.sd.stopFail, w.sd.stopLeaves = true, true
	if _, err := w.simple().Swap(context.Background()); err != nil {
		t.Fatal(err)
	}
	w.must("root/new", "previous/old")
}

func TestFirstMoveFailurePreservesOldTreeAndRestarts(t *testing.T) {
	w := newWorld(t)
	w.fs.failMove = 1
	s := w.simple()
	if _, err := s.Swap(context.Background()); err == nil {
		t.Fatal("swap must fail")
	}
	if r := s.Abort(84); r.Status != 84 {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "!previous", "!stage")
	if !w.sd.started() {
		t.Fatal("prior consumers must restart")
	}
}

func TestFailedRestoreReportsRecoveryPaths(t *testing.T) {
	w := newWorld(t)
	w.fs.failMove = 3
	sw, err := w.withTx().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := sw.Abort(86); r.Status != ExitManualRecovery {
		t.Fatalf("%+v", r)
	}
	w.must("tx/previous/old", "!root")
	for _, p := range []string{"tx", "tx/previous"} {
		if !w.logged(fmt.Sprintf("nas-secret-transaction: retained recovery tree %s\n", w.p(p))) {
			t.Fatalf("missing %s in\n%s", p, w.log.String())
		}
	}
	if w.sd.started() {
		t.Fatal("must not restart")
	}
}

func TestFailedLiveTreeRemovalCannotNestPrevious(t *testing.T) {
	w := newWorld(t)
	sw, err := w.withTx().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	root := w.p("root").String()
	w.fs.failRm = func(p string) bool { return p == root }
	if r := sw.Abort(87); r.Status != ExitManualRecovery {
		t.Fatalf("%+v", r)
	}
	w.must("tx/previous/old", "root/new", "!root/previous")
	if w.fs.moves != 2 {
		t.Fatal("must not attempt restore after live-tree removal fails")
	}
	if w.sd.started() {
		t.Fatal("must not restart new consumers")
	}
}

func TestStageCleanupFailureStillRestartsRestoredConsumers(t *testing.T) {
	w := newWorld(t)
	w.fs.failMove = 2
	s := w.simple()
	if _, err := s.Swap(context.Background()); err == nil {
		t.Fatal("swap must fail")
	}
	stage := w.p("stage").String()
	w.fs.failRm = func(p string) bool { return p == stage }
	if r := s.Abort(88); r.Status != ExitManualRecovery || s.c.phase != PhaseRollbackIncomplete {
		t.Fatalf("%+v", r)
	}
	w.must("root/old", "root/ready", "stage/new", "!previous")
	if !w.sd.started() || !w.logged(stage) {
		t.Fatalf("log:\n%s", w.log.String())
	}
}

func TestStageCleanupWithoutPriorTreeReportsStage(t *testing.T) {
	w := newWorld(t)
	w.sd.active = false
	w.fs.failMove = 1
	_ = os.RemoveAll(filepath.Join(w.dir, "root"))
	s := w.simple()
	if _, err := s.Swap(context.Background()); err == nil {
		t.Fatal("swap must fail")
	}
	stage := w.p("stage").String()
	w.fs.failRm = func(p string) bool { return p == stage }
	if r := s.Abort(89); r.Status != ExitManualRecovery {
		t.Fatalf("%+v", r)
	}
	w.must("stage/new", "!root", "!previous")
	if w.sd.started() || !w.logged(stage) {
		t.Fatal("must report the remaining stage and stay stopped")
	}
}

func TestUncommittedSuccessIsNotSuccess(t *testing.T) {
	w := newWorld(t)
	sw, err := w.simple().Swap(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r := sw.Abort(0); r.Status != ExitManualRecovery || !r.Complete {
		t.Fatalf("%+v", r)
	}
	if !w.logged("transaction exited successfully without commit; rolled back") {
		t.Fatal("the programming error must be visible")
	}
}
