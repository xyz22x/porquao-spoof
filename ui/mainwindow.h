// mainwindow.h — Porquao Spoof main window: tabs Main (target) / Logs (clock)
#pragma once
#include <QMainWindow>
#include <QPlainTextEdit>
#include <QTreeWidget>
#include <QLabel>
#include <QPushButton>
#include <QThread>
#include "toggleswitch.h"

class SpoofWorker;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);

private slots:
    void OnSpoof();
    void OnRestore();
    void OnRunScan();
    void OnLog(const QString& level, const QString& msg);
    void OnDone(int result);

private:
    void BuildUi();
    void ApplyStyles();
    void AppendLog(const QString& level, const QString& msg);
    void RefreshScanTable();
    void SetStatus(const QString& text, const QString& kind);
    void SetBusy(bool busy);

    QLabel*          m_title = nullptr;
    QLabel*          m_statusPill = nullptr;
    ToggleSwitch*    m_swVava = nullptr;
    ToggleSwitch*    m_swRoblox = nullptr;
    ToggleSwitch*    m_swMine = nullptr;
    QPushButton*     m_btnSpoof = nullptr;
    QPushButton*     m_btnRestore = nullptr;
    QPushButton*     m_btnRunScan = nullptr;
    QTreeWidget*     m_scanTable = nullptr;
    QPlainTextEdit*  m_log = nullptr;
    QThread*         m_thread = nullptr;
    SpoofWorker*     m_worker = nullptr;
};
