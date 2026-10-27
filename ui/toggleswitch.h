// toggleswitch.h — animated custom switch widget
#pragma once
#include <QWidget>
#include <QPropertyAnimation>

class ToggleSwitch : public QWidget {
    Q_OBJECT
    Q_PROPERTY(qreal t READ t WRITE setT)

public:
    explicit ToggleSwitch(QWidget* parent = nullptr);
    qreal t() const { return m_t; }
    void setT(qreal v) { m_t = v; update(); }
    bool isChecked() const { return m_checked; }
    void setChecked(bool c) { if (m_checked != c) { m_checked = c; m_anim->stop(); m_anim->setStartValue(m_t); m_anim->setEndValue(c ? 1.0 : 0.0); m_anim->start(); } }
    QSize sizeHint() const override { return { 46, 26 }; }

signals:
    void toggled(bool checked);

protected:
    void paintEvent(QPaintEvent*) override;
    void mousePressEvent(QMouseEvent*) override;
    void keyPressEvent(QKeyEvent*) override;

private:
    bool m_checked = false;
    qreal m_t = 0.0;
    QPropertyAnimation* m_anim = nullptr;
};
