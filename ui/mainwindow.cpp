// mainwindow.cpp — Porquao Spoof UI
// Tab "Main" (target icon): header + three toggle cards + action bar.
// Tab "Logs" (clock icon): vulnerable-driver scan table + colored engine log.
// Spoof/restore run on a worker thread; log lines arrive via queued signals.
// The scan itself is a cheap presence+version check and runs on the UI thread.
#include "mainwindow.h"
#include "toggleswitch.h"
#include "../engine.h"
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QLabel>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QTreeWidget>
#include <QHeaderView>
#include <QFontDatabase>
#include <QTime>
#include <QPainter>
#include <QApplication>

// ---------- worker: engine call lives on its own thread ----------
class SpoofWorker : public QObject {
    Q_OBJECT
public slots:
    void run(uint32_t mask, bool routeA, bool vol) {
        auto sink = [](const char* level, const char* msg) {
            if (g_self) emit g_self->logLine(QString::fromUtf8(level), QString::fromUtf8(msg));
        };
        g_self = this;
        engine::SetLog(sink);
        int r = engine::Spoof(mask, routeA, vol);
        g_self = nullptr;
        emit finished(r);
    }
    void runRestore() {
        auto sink = [](const char* level, const char* msg) {
            if (g_self) emit g_self->logLine(QString::fromUtf8(level), QString::fromUtf8(msg));
        };
        g_self = this;
        engine::SetLog(sink);
        int r = engine::Restore();
        g_self = nullptr;
        emit finished(r);
    }
signals:
    void logLine(const QString& level, const QString& msg);
    void finished(int result);
public:
    static SpoofWorker* g_self;
};
SpoofWorker* SpoofWorker::g_self = nullptr;

// ---------- painted tab icons (no emoji, no external assets) ----------
static QIcon MakeTargetIcon() {
    QPixmap pm(40, 40);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QPen pen(QColor(0x9A, 0xA3, 0xB2), 2.4);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);
    QPointF c(20, 20);
    p.drawEllipse(c, 12, 12);
    p.drawEllipse(c, 5, 5);
    // crosshair ticks
    p.drawLine(QPointF(20, 2),  QPointF(20, 8));
    p.drawLine(QPointF(20, 32), QPointF(20, 38));
    p.drawLine(QPointF(2, 20),  QPointF(8, 20));
    p.drawLine(QPointF(32, 20), QPointF(38, 20));
    return QIcon(pm);
}

static QIcon MakeClockIcon() {
    QPixmap pm(40, 40);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    QPen pen(QColor(0x9A, 0xA3, 0xB2), 2.4);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);
    p.drawEllipse(QPointF(20, 20), 14, 14);
    // hands — 12:00-ish
    p.drawLine(QPointF(20, 20), QPointF(20, 11));   // minute hand up
    p.drawLine(QPointF(20, 20), QPointF(26, 24));   // hour hand down-right
    return QIcon(pm);
}

// ---------- main window ----------
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("Porquao Spoof");
    setWindowIcon(MakeTargetIcon());
    setMinimumSize(600, 620);
    resize(640, 660);

    m_thread = new QThread(this);
    m_worker = new SpoofWorker();
    m_worker->moveToThread(m_thread);
    connect(m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(m_worker, &SpoofWorker::logLine, this, &MainWindow::OnLog, Qt::QueuedConnection);
    connect(m_worker, &SpoofWorker::finished, this, &MainWindow::OnDone, Qt::QueuedConnection);
    m_thread->start();

    BuildUi();
    ApplyStyles();
    RefreshScanTable();
    AppendLog("info", "Porquao Spoof ready — pick a target on Main, watch Logs for errors and vulnerable drivers");
}

void MainWindow::BuildUi() {
    auto* central = new QWidget();
    auto* root = new QVBoxLayout(central);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    auto* tabs = new QTabWidget();
    tabs->setDocumentMode(true);
    tabs->setMovable(false);

    // =================== TAB: MAIN (target icon) ===================
    auto* mainTab = new QWidget();
    auto* mv = new QVBoxLayout(mainTab);
    mv->setContentsMargins(24, 20, 24, 20);
    mv->setSpacing(16);

    auto* header = new QHBoxLayout();
    m_title = new QLabel("Porquao Spoof");
    m_title->setObjectName("title");
    m_statusPill = new QLabel("idle");
    m_statusPill->setObjectName("statusPill");
    header->addWidget(m_title);
    header->addStretch(1);
    header->addWidget(m_statusPill);
    mv->addLayout(header);

    auto* cardsRow = new QHBoxLayout();
    cardsRow->setSpacing(12);
    auto makeCard = [this](const char* name, const char* desc, ToggleSwitch** out) {
        QFrame* card = new QFrame();
        card->setObjectName("card");
        auto* lay = new QHBoxLayout(card);
        lay->setContentsMargins(16, 14, 16, 14);
        lay->setSpacing(12);
        auto* col = new QVBoxLayout();
        col->setSpacing(4);
        auto* t = new QLabel(name);
        t->setObjectName("cardTitle");
        auto* d = new QLabel(desc);
        d->setObjectName("cardDesc");
        d->setWordWrap(true);
        col->addWidget(t);
        col->addWidget(d);
        col->addStretch(1);
        auto* sw = new ToggleSwitch();
        *out = sw;
        lay->addLayout(col, 1);
        lay->addWidget(sw, 0, Qt::AlignVCenter);
        return card;
    };
    cardsRow->addWidget(makeCard("Vava Spoof", "Valorant — boot driver (open source) or BYOVD runtime", &m_swVava));
    cardsRow->addWidget(makeCard("Roblox Spoof", "Session spoof — Hyperion MAC/SMBIOS/guid — resets on reboot", &m_swRoblox));
    cardsRow->addWidget(makeCard("Mine Spoof", "Session spoof — same idea as Roblox — resets on reboot", &m_swMine));
    mv->addLayout(cardsRow);

    auto* actions = new QHBoxLayout();
    actions->setSpacing(10);
    m_btnSpoof = new QPushButton("Spoof Now");
    m_btnSpoof->setObjectName("primary");
    m_btnRestore = new QPushButton("Restore");
    m_btnRestore->setObjectName("secondary");
    actions->addWidget(m_btnSpoof);
    actions->addWidget(m_btnRestore);
    actions->addStretch(1);
    mv->addLayout(actions);
    mv->addStretch(1);

    tabs->addTab(mainTab, MakeTargetIcon(), "Main");

    // =================== TAB: LOGS (clock icon) ===================
    auto* logsTab = new QWidget();
    auto* lv = new QVBoxLayout(logsTab);
    lv->setContentsMargins(24, 20, 24, 20);
    lv->setSpacing(12);

    auto* scanHead = new QHBoxLayout();
    auto* scanLabel = new QLabel("Vulnerable drivers");
    scanLabel->setObjectName("sectionLabel");
    m_btnRunScan = new QPushButton("Run Scan");
    m_btnRunScan->setObjectName("secondary");
    scanHead->addWidget(scanLabel);
    scanHead->addStretch(1);
    scanHead->addWidget(m_btnRunScan);
    lv->addLayout(scanHead);

    m_scanTable = new QTreeWidget();
    m_scanTable->setObjectName("scanTable");
    m_scanTable->setRootIsDecorated(false);
    m_scanTable->setAlternatingRowColors(true);
    m_scanTable->setHeaderLabels({ "FILE", "VENDOR", "CVE", "VERSION", "PRIMITIVE", "STATUS" });
    m_scanTable->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_scanTable->header()->setStretchLastSection(true);
    m_scanTable->setMinimumHeight(200);
    lv->addWidget(m_scanTable, 2);

    m_log = new QPlainTextEdit();
    m_log->setObjectName("log");
    m_log->setReadOnly(true);
    m_log->setMaximumBlockCount(600);
    m_log->setPlaceholderText("engine output shows up here — errors, kernel patch results, scan details");
    lv->addWidget(m_log, 3);

    tabs->addTab(logsTab, MakeClockIcon(), "Logs");
    root->addWidget(tabs, 1);
    setCentralWidget(central);

    connect(m_btnSpoof, &QPushButton::clicked, this, &MainWindow::OnSpoof);
    connect(m_btnRestore, &QPushButton::clicked, this, &MainWindow::OnRestore);
    connect(m_btnRunScan, &QPushButton::clicked, this, &MainWindow::OnRunScan);
}

void MainWindow::ApplyStyles() {
    setStyleSheet(R"(
        QMainWindow { background: #0F1115; }
        QTabWidget::pane { border: none; top: -1px; }
        QTabBar::tab {
            background: transparent; color: #9AA3B2; padding: 8px 18px;
            font-size: 12px; border: none; border-bottom: 2px solid transparent;
        }
        QTabBar::tab:hover { color: #E6E9F0; }
        QTabBar::tab:selected { color: #E6E9F0; border-bottom: 2px solid #6C7CFF; }
        #title { color: #E6E9F0; font-size: 17px; font-weight: 600; letter-spacing: 0.4px; }
        #statusPill {
            color: #9AA3B2; background: #1C2029; border: 1px solid #262B36;
            border-radius: 10px; padding: 3px 12px; font-size: 11px;
        }
        #card { background: #161920; border: 1px solid #262B36; border-radius: 12px; }
        #card:hover { border-color: #3A4460; }
        #cardTitle { color: #E6E9F0; font-size: 13px; font-weight: 600; }
        #cardDesc { color: #9AA3B2; font-size: 11px; }
        #sectionLabel { color: #E6E9F0; font-size: 13px; font-weight: 600; }
        #primary {
            background: #6C7CFF; color: #0F1115; border: none; border-radius: 8px;
            padding: 8px 18px; font-size: 12px; font-weight: 600;
        }
        #primary:hover { background: #7D8BFF; }
        #primary:pressed { background: #5B6BE8; }
        #primary:disabled { background: #3A404D; color: #6B7280; }
        #secondary {
            background: transparent; color: #E6E9F0; border: 1px solid #262B36;
            border-radius: 8px; padding: 8px 16px; font-size: 12px;
        }
        #secondary:hover { border-color: #6C7CFF; color: #8A96FF; }
        #secondary:disabled { color: #6B7280; border-color: #1C2029; }
        #log {
            background: #12141A; border: 1px solid #262B36; border-radius: 10px;
            color: #9AA3B2; font-family: "Consolas"; font-size: 11px;
            padding: 10px; selection-background-color: #6C7CFF;
        }
        #scanTable {
            background: #12141A; border: 1px solid #262B36; border-radius: 10px;
            color: #E6E9F0; font-family: "Consolas"; font-size: 11px;
            alternate-background-color: #151823;
        }
        #scanTable::item { padding: 4px 6px; }
        QHeaderView::section {
            background: #161920; color: #9AA3B2; border: none;
            border-bottom: 1px solid #262B36; padding: 6px 8px;
            font-family: "Segoe UI"; font-size: 11px; font-weight: 600;
        }
        QScrollBar:vertical { background: transparent; width: 8px; margin: 4px; }
        QScrollBar::handle:vertical { background: #262B36; border-radius: 4px; min-height: 24px; }
        QScrollBar::handle:vertical:hover { background: #3A404D; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
    )");
}

void MainWindow::AppendLog(const QString& level, const QString& msg) {
    QString stamp = QTime::currentTime().toString("HH:mm:ss");
    QColor c(0x9A, 0xA3, 0xB2);
    if (level == "ok")   c = QColor(0x34, 0xD3, 0x99);
    if (level == "warn") c = QColor(0xFB, 0xBF, 0x24);
    if (level == "err")  c = QColor(0xF8, 0x71, 0x71);
    QTextCharFormat fmt;
    fmt.setForeground(c);
    QTextCursor cur = m_log->textCursor();
    cur.movePosition(QTextCursor::End);
    cur.insertText(QString("[%1] %2\n").arg(stamp, msg), fmt);
    m_log->setTextCursor(cur);
    m_log->ensureCursorVisible();
}

void MainWindow::RefreshScanTable() {
    m_scanTable->clear();
    auto rows = engine::ScanStructured();
    for (const auto& r : rows) {
        auto* it = new QTreeWidgetItem();
        it->setText(0, QString::fromStdString(r.name));
        it->setText(1, QString::fromStdString(r.vendor));
        it->setText(2, QString::fromStdString(r.cve));
        it->setText(3, r.version.empty() ? "-" : QString::fromStdString(r.version));
        it->setText(4, QString::fromStdString(r.prim));
        it->setText(5, r.present ? "FOUND" : "ABSENT");
        it->setForeground(5, r.present ? QColor(0x34, 0xD3, 0x99) : QColor(0x6B, 0x72, 0x80));
        m_scanTable->addTopLevelItem(it);
    }
    int found = 0;
    for (const auto& r : rows) if (r.present) ++found;
    AppendLog("info", QString("scan: %1/%2 vulnerable drivers present on disk").arg(found).arg(rows.size()).toStdString().c_str());
}

void MainWindow::SetStatus(const QString& text, const QString& kind) {
    m_statusPill->setText(text);
    if (kind == "running")      m_statusPill->setStyleSheet("color: #FBBF24; background: #1C2029; border: 1px solid #262B36; border-radius: 10px; padding: 3px 12px; font-size: 11px;");
    else if (kind == "ok")      m_statusPill->setStyleSheet("color: #34D399; background: #12261F; border: 1px solid #1F4436; border-radius: 10px; padding: 3px 12px; font-size: 11px;");
    else if (kind == "err")     m_statusPill->setStyleSheet("color: #F87171; background: #2A1418; border: 1px solid #52242B; border-radius: 10px; padding: 3px 12px; font-size: 11px;");
    else                        m_statusPill->setStyleSheet("");
}

void MainWindow::SetBusy(bool busy) {
    m_btnSpoof->setEnabled(!busy);
    m_btnRestore->setEnabled(!busy);
    m_btnRunScan->setEnabled(!busy);
    for (auto* sw : { m_swVava, m_swRoblox, m_swMine }) {
        sw->setEnabled(!busy);
        sw->setAttribute(Qt::WA_TransparentForMouseEvents, busy);
    }
    SetStatus(busy ? "running" : "idle", busy ? "running" : "idle");
}

void MainWindow::OnSpoof() {
    uint32_t mask = 0;
    if (m_swVava->isChecked())   mask |= engine::VAVA;
    if (m_swRoblox->isChecked()) mask |= engine::ROBLOX;
    if (m_swMine->isChecked())   mask |= engine::MINE;
    if (!mask) {
        AppendLog("warn", "no target selected — flip a switch first");
        return;
    }
    bool routeA = m_swVava->isChecked();
    SetBusy(true);
    QMetaObject::invokeMethod(m_worker, [this, mask, routeA]() {
        m_worker->run(mask, routeA, false);
    }, Qt::QueuedConnection);
}

void MainWindow::OnRestore() {
    SetBusy(true);
    QMetaObject::invokeMethod(m_worker, [this]() {
        m_worker->runRestore();
    }, Qt::QueuedConnection);
}

void MainWindow::OnRunScan() {
    SetBusy(true);
    RefreshScanTable();
    SetBusy(false);
}

void MainWindow::OnLog(const QString& level, const QString& msg) {
    AppendLog(level, msg);
    if (msg.contains("=== spoof complete")) SetStatus("spoofed", "ok");
    if (msg.contains("restore complete"))   SetStatus("restored", "ok");
    if (msg.contains("administrator token required")) SetStatus("admin required", "err");
    if (msg.contains("failed") || msg.contains("err")) {
        // keep the pill accurate: errors surface in Logs tab
    }
}

void MainWindow::OnDone(int result) {
    SetBusy(false);
    if (result == 0)       SetStatus("done", "ok");
    else if (result == -100) SetStatus("admin required", "err");
    else                   SetStatus("failed", "err");
}

#include "mainwindow.moc"
