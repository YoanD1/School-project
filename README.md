# AI система за откриване на аномалии в мрежа
**11 клас — „Програмиране на ИИ" | Задание 2**

Конзолно Python приложение, което симулира мрежов трафик, открива подозрително поведение чрез хибриден AI модел и записва резултатите в SQLite база данни и файлове.

---

## Как се стартира

```bash
# Инсталирай зависимости (само стандартна библиотека — нищо допълнително)
python main.py        # пълен pipeline, записва final_report.json
python demo.py        # интерактивна демонстрация, раздел по раздел
```

---

## Структура на проекта

```
School-project/
├── main.py                   # входна точка — пълен Week-4 pipeline
├── demo.py                   # интерактивна демо (за защита)
├── data/
│   └── sample_traffic.csv    # 35 ръчно съставени labeled пакета
├── db/
│   └── network_monitor.db    # SQLite база (създава се при стартиране)
├── logs/
│   ├── network_monitor.log   # текстов лог
│   ├── anomalies_export.json
│   ├── anomalies_export.csv
│   └── final_report.json     # финален отчет (Week 4)
├── src/
│   ├── network_packet.py     # модел на данните
│   ├── anomaly_detector.py   # AI/ML логика
│   ├── model_evaluator.py    # оценка на модела
│   ├── traffic_analyzer.py   # LINQ-style анализ
│   ├── traffic_simulator.py  # генератор на синтетичен трафик
│   ├── monitoring_service.py # централен контролер
│   ├── event_manager.py      # Observer pattern + event args
│   ├── database_service.py   # SQLite CRUD + агрегации
│   ├── file_logger.py        # лог, JSON, CSV четене/запис
│   └── exceptions.py         # custom exceptions
└── docs/
    ├── ai_diary.md           # AI дневник (анти-AI изискване)
    └── presentation_notes.md # бележки за защита
```

---

## Класове

| Клас | Роля | Файл |
|------|------|------|
| `NetworkPacket` | Модел на данните (dataclass) | `network_packet.py` |
| `AnomalyDetector` | AI/ML логика — rule-based + Z-score | `anomaly_detector.py` |
| `ModelEvaluator` | Оценка: accuracy, recall, confusion matrix | `model_evaluator.py` |
| `TrafficAnalyzer` | LINQ анализ — map, filter, reduce, groupby | `traffic_analyzer.py` |
| `TrafficSimulator` | Генерира нормален, DDoS и port-scan трафик | `traffic_simulator.py` |
| `MonitoringService` | Централен оркестратор — свързва всички класове | `monitoring_service.py` |
| `EventManager` | Observer pattern — 3 събития, 2+ слушатели всяко | `event_manager.py` |
| `DatabaseService` | SQLite CRUD + SQL агрегации | `database_service.py` |
| `FileLogger` | Лог, JSON/CSV запис и четене | `file_logger.py` |

---

## AI компонент — AnomalyDetector

Хибриден двустъпков модел:

**Стъпка 1 — rule-based:**
- `packets_per_second >= 300` → **ddos** (confidence = 1.0)
- `failed_connections >= 20` → **suspicious** (confidence = 1.0)

**Стъпка 2 — статистически Z-score:**
- Обучава се на нормален трафик (`detector.train(normal_packets)`)
- Изчислява Z-score по `packets_per_second`, `bytes_per_second`, `failed_connections`
- `max_z >= 2.5` → **suspicious**, confidence = min(z/5, 1.0)
- Иначе → **normal**

**Точност на labeled данните:** 100% (35/35 правилно класифицирани)

---

## Събития (Observer Pattern)

| Събитие | Кога се изстрелва | Слушатели |
|---------|------------------|-----------|
| `on_anomaly_detected` | suspicious пакет | console print + file log |
| `on_ddos_suspected` | ddos пакет | console print + file log |
| `on_unusual_traffic` | bytes/s > 80 000 | console print + file log |

---

## База данни (SQLite)

**3 таблици:**
- `devices` — уникални IP адреси, first/last seen
- `packets` — всеки обработен пакет с label
- `anomalies` — логирани аномалии с severity и is_resolved флаг

**CRUD операции:** insert, select (по label), update (resolve), upsert (devices)
**SQL агрегации:** GROUP BY label/severity, AVG(pps), COUNT

---

## LINQ еквиваленти (Python)

```python
# list comprehension
high_risk = [p for p in packets if p.packets_per_second > 200]

# map
risk_scores = list(map(lambda p: (p.source_ip, p.packets_per_second * 0.4 + ...), packets))

# filter
critical = filter(lambda x: x[1] >= 80.0, risk_scores)

# reduce
total_bytes = reduce(lambda acc, p: acc + p.bytes_per_second, packets, 0.0)

# sorted + groupby
grouped = {proto: list(g) for proto, g in groupby(sorted(packets, key=...), key=...)}
```

---

## Custom Exceptions

| Клас | Кога се хвърля |
|------|---------------|
| `PacketParseError` | Невалиден CSV ред |
| `InsufficientTrainingDataError` | Опит за тренировка с < 2 нормални пакета |
| `DetectionError` | Грешка в predict() |
| `DatabaseError` | SQLite операция се проваля |
| `FileExportError` | Запис или четене на файл се проваля |

---

## Собствени данни

`data/sample_traffic.csv` — 35 ръчно съставени записа:
- 20 нормални пакета (HTTP, HTTPS, DNS от вътрешна мрежа)
- 5 DDoS пакета (>660 pps от известни attacker IP)
- 10 suspicious пакета (port scan, failed connections >= 28)