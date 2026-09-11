package jobs

import "testing"

func TestCanTransition(t *testing.T) {
	ok := [][2]Status{
		{StatusQueued, StatusRunning},
		{StatusQueued, StatusCancelled},
		{StatusRunning, StatusPaused},
		{StatusRunning, StatusCompleted},
		{StatusRunning, StatusPartiallyCompleted},
		{StatusPaused, StatusRunning},
	}
	for _, p := range ok {
		if !CanTransition(p[0], p[1]) {
			t.Errorf("%s -> %s should be allowed", p[0], p[1])
		}
	}
	bad := [][2]Status{
		{StatusCompleted, StatusRunning},
		{StatusCancelled, StatusQueued},
		{StatusFailed, StatusRunning},
		{StatusQueued, StatusCompleted},
		{StatusPaused, StatusCompleted},
	}
	for _, p := range bad {
		if CanTransition(p[0], p[1]) {
			t.Errorf("%s -> %s should be rejected", p[0], p[1])
		}
	}
}

func TestTerminal(t *testing.T) {
	for _, s := range []Status{StatusCompleted, StatusFailed, StatusCancelled, StatusPartiallyCompleted} {
		if !s.Terminal() {
			t.Errorf("%s should be terminal", s)
		}
	}
	for _, s := range []Status{StatusQueued, StatusRunning, StatusPaused} {
		if s.Terminal() {
			t.Errorf("%s should not be terminal", s)
		}
	}
}
