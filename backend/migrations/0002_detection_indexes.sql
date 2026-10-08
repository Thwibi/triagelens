-- Detection run hot paths (spec 04 section 2).
--
-- Two queries dominate every detection run and neither was indexed in 0001:
--
-- * rules filter on ``event_action`` (built-in rules 100% do, web rules often
--   do) and the routing predicate degenerates to ``log_type``/``ls_category``
--   with the selection on top. ``events(case_id, event_action)`` turns the
--   per-rule scan into a range walk on one index.
--
-- * alert evidence joins ``alert_events`` to ``events`` by event id when the
--   stored sample is expanded, and ``alert_events(event_id)`` is the only
--   direction not covered by its composite primary key.
CREATE INDEX idx_ev_action         ON events(case_id, event_action);
CREATE INDEX idx_alert_events_event ON alert_events(event_id);