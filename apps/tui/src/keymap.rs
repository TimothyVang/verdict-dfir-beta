//! Key bindings: translate a raw key into a semantic [`Action`].
//!
//! Kept separate from the event loop and the [`crate::app::App`] state so
//! the binding table can be unit-tested without a terminal. Bindings:
//! `q` / `Ctrl-C` quit; arrows or `j`/`k` navigate; `Enter` drills into a
//! Finding; `Esc` goes back (or closes help); `?` toggles help.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// A semantic action, decoupled from the physical key that produced it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    Up,
    Down,
    Enter,
    Back,
    ToggleHelp,
    None,
}

/// Map a key event to an [`Action`]. Unbound keys map to [`Action::None`].
#[must_use]
pub const fn action_for(key: KeyEvent) -> Action {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return Action::Quit;
    }
    match key.code {
        KeyCode::Char('q') => Action::Quit,
        KeyCode::Up | KeyCode::Char('k') => Action::Up,
        KeyCode::Down | KeyCode::Char('j') => Action::Down,
        KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => Action::Enter,
        KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left => Action::Back,
        KeyCode::Char('?') => Action::ToggleHelp,
        _ => Action::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    #[test]
    fn quits_on_q_and_ctrl_c() {
        assert_eq!(action_for(key(KeyCode::Char('q'))), Action::Quit);
        assert_eq!(
            action_for(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Action::Quit
        );
    }

    #[test]
    fn navigation_keys_map_to_directions() {
        assert_eq!(action_for(key(KeyCode::Up)), Action::Up);
        assert_eq!(action_for(key(KeyCode::Char('k'))), Action::Up);
        assert_eq!(action_for(key(KeyCode::Down)), Action::Down);
        assert_eq!(action_for(key(KeyCode::Char('j'))), Action::Down);
        assert_eq!(action_for(key(KeyCode::Enter)), Action::Enter);
        assert_eq!(action_for(key(KeyCode::Esc)), Action::Back);
        assert_eq!(action_for(key(KeyCode::Char('?'))), Action::ToggleHelp);
    }

    #[test]
    fn unbound_key_is_none() {
        assert_eq!(action_for(key(KeyCode::Char('z'))), Action::None);
    }
}
