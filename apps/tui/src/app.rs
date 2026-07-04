//! Application state and the reducer that applies an [`Action`].
//!
//! The state is a small value: the loaded case, which pane is focused, the
//! selected Finding, the detail scroll offset, and whether the help
//! overlay is open. It holds no evidence handle and performs no IO — it
//! only navigates already-loaded data.

use ratatui::widgets::ListState;

use crate::case::CaseBundle;
use crate::keymap::Action;

/// Which pane currently has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    /// Verdict header + scrollable Findings list.
    List,
    /// Verdict header + the selected Finding's custody detail.
    Detail,
}

/// The whole viewer state.
pub struct App {
    pub case: CaseBundle,
    pub view: View,
    pub list_state: ListState,
    pub detail_scroll: u16,
    pub show_help: bool,
    pub should_quit: bool,
}

impl App {
    /// Build the initial state for a loaded case. Selects the first
    /// Finding when the case has any.
    #[must_use]
    pub fn new(case: CaseBundle) -> Self {
        let mut list_state = ListState::default();
        if !case.findings.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            case,
            view: View::List,
            list_state,
            detail_scroll: 0,
            show_help: false,
            should_quit: false,
        }
    }

    /// Index of the selected Finding, if any.
    #[must_use]
    pub const fn selected(&self) -> Option<usize> {
        self.list_state.selected()
    }

    /// Number of Findings in the case.
    #[must_use]
    pub const fn finding_count(&self) -> usize {
        self.case.findings.len()
    }

    /// Apply a semantic action, mutating state in place.
    pub fn apply(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::ToggleHelp => self.show_help = !self.show_help,
            Action::Up => self.move_up(),
            Action::Down => self.move_down(),
            Action::Enter => self.drill_in(),
            Action::Back => self.go_back(),
            Action::None => {}
        }
    }

    fn move_up(&mut self) {
        if self.show_help {
            return;
        }
        match self.view {
            View::List => self.select_prev(),
            View::Detail => self.detail_scroll = self.detail_scroll.saturating_sub(1),
        }
    }

    fn move_down(&mut self) {
        if self.show_help {
            return;
        }
        match self.view {
            View::List => self.select_next(),
            View::Detail => self.detail_scroll = self.detail_scroll.saturating_add(1),
        }
    }

    fn drill_in(&mut self) {
        if self.show_help {
            return;
        }
        if self.view == View::List && self.selected().is_some() {
            self.view = View::Detail;
            self.detail_scroll = 0;
        }
    }

    fn go_back(&mut self) {
        if self.show_help {
            self.show_help = false;
            return;
        }
        if self.view == View::Detail {
            self.view = View::List;
        }
    }

    fn select_prev(&mut self) {
        if self.finding_count() == 0 {
            return;
        }
        let current = self.selected().unwrap_or(0);
        self.list_state.select(Some(current.saturating_sub(1)));
    }

    fn select_next(&mut self) {
        let count = self.finding_count();
        if count == 0 {
            return;
        }
        let current = self.selected().unwrap_or(0);
        let next = current.saturating_add(1).min(count - 1);
        self.list_state.select(Some(next));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::{CaseBundle, Finding};
    use std::path::PathBuf;

    fn app_with(findings: usize) -> App {
        let case = CaseBundle {
            dir: PathBuf::from("/case/example"),
            verdict_word: Some("SUSPICIOUS".into()),
            case_id: Some("c-1".into()),
            findings: vec![Finding::default(); findings],
            tally: None,
            artifact_classes: None,
            manifest_verify: None,
        };
        App::new(case)
    }

    #[test]
    fn selects_first_finding_when_present() {
        assert_eq!(app_with(3).selected(), Some(0));
        assert_eq!(app_with(0).selected(), None);
    }

    #[test]
    fn navigation_clamps_within_bounds() {
        let mut app = app_with(2);
        app.apply(Action::Up); // already at 0
        assert_eq!(app.selected(), Some(0));
        app.apply(Action::Down);
        assert_eq!(app.selected(), Some(1));
        app.apply(Action::Down); // clamp at last
        assert_eq!(app.selected(), Some(1));
    }

    #[test]
    fn enter_drills_in_and_esc_returns() {
        let mut app = app_with(1);
        assert_eq!(app.view, View::List);
        app.apply(Action::Enter);
        assert_eq!(app.view, View::Detail);
        app.apply(Action::Back);
        assert_eq!(app.view, View::List);
    }

    #[test]
    fn detail_arrows_scroll_not_select() {
        let mut app = app_with(2);
        app.apply(Action::Enter);
        app.apply(Action::Down);
        assert_eq!(app.detail_scroll, 1);
        assert_eq!(app.selected(), Some(0)); // selection unchanged in detail
        app.apply(Action::Up);
        assert_eq!(app.detail_scroll, 0);
    }

    #[test]
    fn help_toggles_and_esc_closes_it_first() {
        let mut app = app_with(1);
        app.apply(Action::ToggleHelp);
        assert!(app.show_help);
        app.apply(Action::Back); // closes help, does not leave detail
        assert!(!app.show_help);
        assert_eq!(app.view, View::List);
    }

    #[test]
    fn quit_sets_flag() {
        let mut app = app_with(1);
        assert!(!app.should_quit);
        app.apply(Action::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn enter_is_noop_without_findings() {
        let mut app = app_with(0);
        app.apply(Action::Enter);
        assert_eq!(app.view, View::List);
    }
}
