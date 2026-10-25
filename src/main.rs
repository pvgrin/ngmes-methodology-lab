//! Ограниченные два шага NML-01. JSON и SQLite обслуживает отдельный адаптер.
use std::io::{self, BufRead, Read, Write};

#[derive(Debug)]
struct ResultData {
    id: String,
    source: String,
    revision: u64,
    value: i64,
    event_at: String,
    received_at: String,
}

struct Decision {
    id: String,
    role: String,
    action: String,
    reason: String,
    at: String,
    recipient: String,
    revision: u64,
    accepted: bool,
}

struct State {
    batch: String,
    sample: String,
    indicator: String,
    rule: String,
    unit: String,
    sampled: u64,
    now: u64,
    deadline: u64,
    lower: i64,
    upper: i64,
    delayed: bool,
    result: Option<ResultData>,
    deliveries: u64,
    decisions: Vec<Decision>,
    read_allowed: bool,
}

fn json_text(value: &str) -> String {
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c <= '\u{1f}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn reason(hex: &str) -> Result<String, String> {
    if hex.is_empty() || hex.len() > 4096 || !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return Err("Недопустимое основание решения".into());
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "Недопустимое основание решения")?;
    let text = String::from_utf8(bytes).map_err(|_| "Основание должно быть UTF-8")?;
    if text.trim().is_empty() {
        return Err("Основание не может быть пустым".into());
    }
    Ok(text)
}

fn number<T: std::str::FromStr>(s: &str) -> Result<T, String> {
    s.parse().map_err(|_| "Некорректное число".into())
}

fn token(s: &str) -> Result<String, String> {
    if s.is_empty()
        || s.len() > 64
        || !s
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"-_.:/".contains(&c))
    {
        return Err("Недопустимый идентификатор или единица".into());
    }
    Ok(s.to_owned())
}

impl State {
    fn init(p: &[&str]) -> Result<Self, String> {
        if p.len() != 11 || p[0] != "init" {
            return Err("Первая запись должна быть регистрацией".into());
        }
        let sampled = number::<u64>(p[4])?;
        let now = number::<u64>(p[5])?;
        let lower = number::<i64>(p[7])?;
        let upper = number::<i64>(p[8])?;
        let wait = number::<u64>(p[9])?;
        if sampled > now || lower > upper || wait == 0 || wait > 1440 || p[10] != "mg/L" {
            return Err("Недопустимая регистрация или политика".into());
        }
        let deadline = sampled.checked_add(wait * 60).ok_or("Переполнение срока")?;
        if now >= deadline {
            return Err("Поздняя регистрация пока вне первого шага".into());
        }
        Ok(Self {
            batch: token(p[1])?,
            sample: token(p[2])?,
            indicator: token(p[3])?,
            rule: token(p[6])?,
            unit: token(p[10])?,
            sampled,
            now,
            deadline,
            lower,
            upper,
            delayed: false,
            result: None,
            deliveries: 0,
            decisions: Vec::new(),
            read_allowed: false,
        })
    }

    fn apply(&mut self, p: &[&str]) -> Result<(), String> {
        match p.first().copied() {
            Some("tick") if p.len() == 2 => {
                let now = number::<u64>(p[1])?;
                if now < self.now {
                    return Err("Время не может идти назад".into());
                }
                self.now = now;
                if self.result.is_none() && now >= self.deadline {
                    self.delayed = true;
                }
            }
            Some("result") if p.len() == 13 => {
                let id = token(p[1])?;
                let source = token(p[2])?;
                let revision = number::<u64>(p[6])?;
                let event = number::<u64>(p[7])?;
                let received = number::<u64>(p[8])?;
                let value = number::<i64>(p[9])?;
                let event_at = token(p[11])?;
                let received_at = token(p[12])?;
                if p[3] != self.batch || p[4] != self.sample || p[5] != self.indicator {
                    return Err("Неизвестная партия, проба или показатель".into());
                }
                if p[10] != self.unit
                    || revision != 1
                    || event < self.sampled
                    || event > received
                    || received < self.now
                {
                    return Err("Непригодный результат или порядок времени".into());
                }
                if let Some(previous) = &self.result {
                    if previous.id != id
                        || previous.source != source
                        || previous.revision != revision
                        || previous.value != value
                        || previous.event_at != event_at
                    {
                        return Err(
                            "Исправления, конфликты и другой результат пока не поддерживаются"
                                .into(),
                        );
                    }
                    self.deliveries += 1;
                    self.now = received;
                    self.read_allowed = false;
                    return Ok(());
                }
                if received >= self.deadline {
                    return Err("Первый результат на/после срока пока не поддерживается".into());
                }
                self.now = received;
                self.result = Some(ResultData {
                    id,
                    source,
                    revision,
                    value,
                    event_at,
                    received_at,
                });
                self.deliveries = 1;
                self.read_allowed = false;
            }
            Some("read_report") if p.len() == 3 => {
                let at = number::<u64>(p[1])?;
                if at < self.now || !["quality_responsible", "site_supervisor"].contains(&p[2]) {
                    return Err("Просмотр не разрешён или время идёт назад".into());
                }
                self.now = at;
                if self.result.is_none() && at >= self.deadline {
                    self.delayed = true;
                }
                self.read_allowed = true;
            }
            Some("decision") if p.len() == 10 => {
                let id = token(p[1])?;
                let role = token(p[2])?;
                let action = token(p[3])?;
                let basis = reason(p[4])?;
                let revision = number::<u64>(p[6])?;
                let at = number::<u64>(p[7])?;
                let at_text = token(p[8])?;
                let recipient = if p[9] == "-" {
                    String::new()
                } else {
                    token(p[9])?
                };
                let result = self.result.as_ref().ok_or("Нет результата для решения")?;
                if self.decisions.iter().any(|d| d.id == id) {
                    return Err("Идентификатор решения уже использован".into());
                }
                if at < self.now
                    || p[5] != self.rule
                    || revision != result.revision
                    || (self.lower..=self.upper).contains(&result.value)
                    || !["check", "request_clarification", "escalate"].contains(&action.as_str())
                    || (action == "escalate") == recipient.is_empty()
                {
                    return Err("Неверное действие, основание, получатель или время решения".into());
                }
                let accepted = role == "quality_responsible";
                self.decisions.push(Decision {
                    id,
                    role,
                    action,
                    reason: basis,
                    at: at_text,
                    recipient,
                    revision,
                    accepted,
                });
                self.now = at;
                self.read_allowed = false;
            }
            _ => return Err("Неизвестная команда или состав полей".into()),
        }
        Ok(())
    }

    fn report(&self) -> String {
        let (quality, reason) = match &self.result {
            None => ("unknown", "Пригодный результат отсутствует"),
            Some(r) if (self.lower..=self.upper).contains(&r.value) => {
                ("conforming", "Показатель находится во включённом интервале")
            }
            Some(_) => ("nonconforming", "Показатель вне допустимого интервала"),
        };
        let overdue = self.result.is_none() && self.now >= self.deadline;
        let question = self.delayed || quality == "nonconforming";
        let mut action = if overdue {
            "quality_responsible_request_clarification"
        } else if quality == "nonconforming" {
            "quality_responsible_review"
        } else {
            "none"
        };
        let accepted: Vec<_> = self.decisions.iter().filter(|d| d.accepted).collect();
        let rejected: Vec<_> = self.decisions.iter().filter(|d| !d.accepted).collect();
        let mut review = if question { "open" } else { "not_required" };
        if let Some(d) = accepted.last() {
            (review, action) = match d.action.as_str() {
                "check" => ("checked", "none"),
                "request_clarification" => ("clarification_requested", "await_clarification"),
                "escalate" => ("escalated", "authorized_person_review"),
                _ => unreachable!(),
            };
        }
        let mut text = format!(
            r#"{{"batch_id":"{}","sample_id":"{}","indicator":"{}","unit":"{}","rule_version":"{}","quality":"{}","quality_reason":"{}","data_status":"{}","review":"{}","next_action":"{}","permission":"not_issued","overdue":{},"delay_episodes":{},"logical_exceptions":{}"#,
            self.batch,
            self.sample,
            self.indicator,
            self.unit,
            self.rule,
            quality,
            reason,
            if self.result.is_some() {
                "received"
            } else {
                "waiting"
            },
            review,
            action,
            overdue,
            u8::from(self.delayed),
            u8::from(question)
        );
        text.push_str(&format!(r#", "logical_results":{},"deliveries":{},"accepted_decisions":{},"rejected_decisions":{},"report_read_allowed":{}"#,
            u8::from(self.result.is_some()),self.deliveries,accepted.len(),rejected.len(),self.read_allowed));
        if let Some(r) = &self.result {
            text.push_str(&format!(
                r#", "source":"{}","revision":{},"value":{},"event_at":"{}","received_at":"{}""#,
                r.source, r.revision, r.value, r.event_at, r.received_at
            ));
            text.push_str(&format!(
                r#", "stored_revisions":[{}],"event_id":{},"first_received_at":{}"#,
                r.revision,
                json_text(&r.id),
                json_text(&r.received_at)
            ));
        }
        if let Some(d) = accepted.last() {
            text.push_str(&format!(r#", "decision_id":{},"decision_basis_revision":{},"decision_role":{},"decision_action":{},"decision_reason":{},"decision_at":{},"decision_rule_version":{},"decision_recipient":{}"#,
                json_text(&d.id),d.revision,json_text(&d.role),json_text(&d.action),json_text(&d.reason),json_text(&d.at),json_text(&self.rule),json_text(&d.recipient)));
        }
        if accepted.len() > 1 {
            text.push_str(&format!(
                r#", "history_retains_decision":{}"#,
                json_text(&accepted[0].id)
            ));
        }
        if let Some(d) = rejected.last() {
            text.push_str(&format!(
                r#", "rejected_decision_id":{},"decision_rejection_reason":"role_not_authorized""#,
                json_text(&d.id)
            ));
        }
        if let Some(d) = self.decisions.last() {
            text.push_str(&format!(r#", "last_decision_accepted":{}"#, d.accepted));
        }
        text.push('}');
        text
    }
}

fn run() -> Result<(), String> {
    let mut input = io::stdin().lock();
    let mut output = io::stdout().lock();
    let mut state: Option<State> = None;
    let mut count = 0;
    loop {
        let mut bytes = Vec::new();
        let size = (&mut input)
            .take(65537)
            .read_until(b'\n', &mut bytes)
            .map_err(|e| e.to_string())?;
        if size == 0 {
            break;
        }
        count += 1;
        if size > 65536 || count > 1000 {
            return Err("Превышен предел входа".into());
        }
        let line = std::str::from_utf8(&bytes).map_err(|_| "Нужен UTF-8")?;
        let parts: Vec<_> = line.trim_end_matches(['\n', '\r']).split('\t').collect();
        if let Some(current) = &mut state {
            current.apply(&parts)?;
        } else {
            state = Some(State::init(&parts)?);
        }
        writeln!(output, "{}", state.as_ref().unwrap().report()).map_err(|e| e.to_string())?;
        output.flush().map_err(|e| e.to_string())?;
    }
    if state.is_none() {
        return Err("Нет регистрации".into());
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Ошибка NML-01: {error}");
        std::process::exit(2);
    }
}
