# Бележки за презентация — AI Мрежов Монитор

> Структурата следва задължителните 8 точки от финалната презентация.

---

## 1. Идея

**Какъв проблем решаваме?**
Мрежовите администратори не могат да наблюдават ръчно хиляди пакети в секунда. Системата автоматично класифицира трафика като нормален, подозрителен или DDoS атака и алармира в реално време.

**Сценарий:**
Училищна мрежа получава внезапен spike от 850 пакета/секунда от непознат IP. Системата го открива, записва го в базата данни и изпраща alert на администратора — без човешка намеса.

---

## 2. Архитектура

```
TrafficSimulator ──► MonitoringService ──► AnomalyDetector
      │                     │                     │
      │              EventManager           ModelEvaluator
      │             ╱    │    ╲
      │      Listener Listener Listener
      │
      └──► TrafficAnalyzer (LINQ)
      └──► DatabaseService (SQLite)
      └──► FileLogger (JSON/CSV/log)
```

**Поток на данните:**
1. `TrafficSimulator` генерира пакети
2. `MonitoringService.process_packet()` оркестрира всичко
3. `AnomalyDetector.predict()` връща label + confidence
4. `EventManager.dispatch()` уведомява слушателите
5. `DatabaseService.insert_packet()` записва в SQLite
6. `FileLogger` пише лог

---

## 3. AI модел

**Тип:** Хибриден — rule-based + статистически Z-score

**Стъпка 1 — правила (бърза проверка):**
```
pps >= 300        → ddos       (confidence 1.0)
failed_conn >= 20 → suspicious (confidence 1.0)
```

**Стъпка 2 — Z-score (за гранични случаи):**
```
z = |x - baseline_mean| / baseline_stdev
max_z >= 2.5 → suspicious
```

**Тренировка:** 20 нормални пакета от `data/sample_traffic.csv`

**Резултат:** 100% точност на 35 labeled пакета (35/35)

**Демо код (live промяна при защита):**
```python
# Промени прага и виж как се променя класификацията
detector.DDOS_PPS_THRESHOLD = 200   # по-строг
detector.Z_SCORE_THRESHOLD = 2.0    # по-чувствителен
```

---

## 4. Събития (Observer Pattern)

**3 събития, всяко с 2 слушатели:**

| Събитие | Listener 1 | Listener 2 |
|---------|-----------|-----------|
| `on_anomaly_detected` | print на конзолата | запис в лог файл |
| `on_ddos_suspected` | print [CRITICAL] | запис като ERROR |
| `on_unusual_traffic` | print [WARNING] | запис в лог файл |

**Как работи:**
```python
events.subscribe("on_ddos_suspected", my_callback)
events.dispatch("on_ddos_suspected", DDoSEventArgs(attacker_ip=...))
# → извиква my_callback(args) автоматично
```

---

## 5. Данни

**Собствени данни:** `data/sample_traffic.csv` — 35 записа, 3 категории

| Тип | Брой | Характеристики |
|-----|------|---------------|
| normal | 20 | pps 6–25, failed 0–1 |
| ddos | 5 | pps 660–1100, failed 0 |
| suspicious | 10 | failed 28–50, pps 88–145 |

**LINQ анализ:**
- `map` → risk score за всеки пакет
- `filter` → само критичните IP адреси
- `reduce` → общ брой bytes и failed connections
- `groupby` → пакети групирани по протокол
- `sorted` → топ 5 IP по брой пакети

---

## 6. Демонстрация

```bash
python demo.py
```

Секции при демото:
1. NetworkPacket — създаване и инспектиране
2. Custom exceptions — InsufficientTrainingDataError, DatabaseError
3. AnomalyDetector — тренировка и предсказване
4. EventManager — Observer pattern live
5. DatabaseService — CRUD на 3 таблици
6. TrafficAnalyzer — LINQ queries
7. TrafficSimulator — генериране на пакети
8. MonitoringService — пълен pipeline
9. FileLogger — JSON/CSV export
10. ModelEvaluator — confusion matrix
11. reduce / map / filter methods
12. read_from_json / read_from_csv

---

## 7. Ограничения

- **Малък dataset** — тренировка на 20 пакета; реален модел изисква хиляди
- **Без времева памет** — всеки пакет се оценява независимо; бавни атаки се пропускат
- **Z-score ≠ Machine Learning** — предполага нормално разпределение; реалният трафик е скосен
- **Симулирани данни** — реалният мрежов трафик е по-сложен и шумен
- **Без persistence на модела** — при всяко стартиране тренировката се повтаря

---

## 8. Подобрения

- **Sliding window** — оценяване на трафик за последните N секунди вместо по 1 пакет
- **Запазване на baseline** в JSON — зареждане без повторна тренировка
- **scikit-learn Decision Tree** — по-добра точност с повече features
- **Уеб dashboard** (Flask/Tkinter) — визуализация на трафика на живо
- **Trusted devices** — whitelist на познати MAC адреси

---

## Въпроси за защита — кратки отговори

**Как работи AI моделът?**
Двустъпков: първо правила (threshold), после Z-score спрямо baseline от нормален трафик.

**Какво предсказва?**
Класифицира пакет като `normal`, `suspicious` или `ddos` с confidence стойност.

**Какви данни използва?**
`packets_per_second`, `bytes_per_second`, `failed_connections`.

**Как комуникират класовете?**
`MonitoringService` свързва всички — получава пакет, извиква detector, после db, после events.

**Как работят събитията?**
`EventManager` пази `dict` от списъци с callback-и. `dispatch()` обхожда списъка и извиква всеки.

**Как се записват данните?**
SQLite за пакети/аномалии/devices; JSON и CSV за export; `.log` файл за текстов лог.

**Какви грешки обработваш?**
5 custom exceptions — за парсване, тренировка, detection, база данни, файлове.

**Как би подобрил модела?**
Sliding window за временен контекст + Decision Tree за по-сложни patterns.
