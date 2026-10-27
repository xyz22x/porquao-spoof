// main.cpp — Porquao Spoof entry (Qt6 Widgets, dark native look)
#include "mainwindow.h"
#include <QApplication>
#include <QFontDatabase>
#include <QFont>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    app.setApplicationName("Porquao Spoof");
    app.setOrganizationName("PQ");
    app.setWindowIcon(QIcon());
    // Segoe UI Variable Display when present, Segoe UI otherwise
    QFont f = QFontDatabase::systemFont(QFontDatabase::GeneralFont);
    if (QFontDatabase::families().contains("Segoe UI Variable Display"))
        f.setFamily("Segoe UI Variable Display");
    else
        f.setFamily("Segoe UI");
    app.setFont(f);
    MainWindow w;
    w.show();
    return app.exec();
}
