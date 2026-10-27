// toggleswitch.cpp — knob slide with outCubic easing, hover + focus states
#include "toggleswitch.h"
#include <QPainter>
#include <QMouseEvent>
#include <QKeyEvent>
#include <cmath>

namespace {
    const QColor TrackOff(0x3A, 0x40, 0x4D);
    const QColor TrackOn(0x6C, 0x7C, 0xFF);
    const QColor TrackHover(0x4A, 0x50, 0x5E);
    const QColor Knob(0xE6, 0xE9, 0xF0);
    const QColor Focus(0x8A, 0x96, 0xFF);
}

ToggleSwitch::ToggleSwitch(QWidget* parent) : QWidget(parent) {
    setCursor(Qt::PointingHandCursor);
    setFocusPolicy(Qt::StrongFocus);
    setFixedSize(46, 26);
    m_anim = new QPropertyAnimation(this, "t", this);
    m_anim->setDuration(160);
    m_anim->setEasingCurve(QEasingCurve::OutCubic);
}

void ToggleSwitch::paintEvent(QPaintEvent*) {
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);

    const qreal w = width(), h = height();
    const qreal trackH = 24.0, trackW = 44.0;
    const QRectF trackR((w - trackW) / 2, (h - trackH) / 2, trackW, trackH);

    QColor track = m_checked ? TrackOn : (underMouse() ? TrackHover : TrackOff);
    if (m_checked && underMouse()) track = TrackOn.lighter(112);

    p.setPen(Qt::NoPen);
    p.setBrush(track);
    p.drawRoundedRect(trackR, trackH / 2, trackH / 2);

    // knob — slides across the track with a subtle shadow
    const qreal knobD = 18.0;
    const qreal x0 = trackR.left() + (trackH - knobD) / 2;
    const qreal x1 = trackR.right() - knobD - (trackH - knobD) / 2;
    const qreal kx = x0 + (x1 - x0) * m_t;
    const qreal ky = trackR.top() + (trackH - knobD) / 2;

    if (hasFocus()) {
        QPen fp(Focus, 2);
        p.setPen(fp);
        p.setBrush(Qt::NoBrush);
        QRectF fr = trackR.adjusted(-3, -3, 3, 3);
        p.drawRoundedRect(fr, fr.height() / 2, fr.height() / 2);
        p.setPen(Qt::NoPen);
    }

    // knob shadow
    QColor shadow(0, 0, 0, 90);
    p.setBrush(shadow);
    p.drawEllipse(QPointF(kx + knobD / 2 + 0.5, ky + knobD / 2 + 1.5), knobD / 2, knobD / 2);

    p.setBrush(Knob);
    p.drawEllipse(QPointF(kx + knobD / 2, ky + knobD / 2), knobD / 2, knobD / 2);
}

void ToggleSwitch::mousePressEvent(QMouseEvent* e) {
    if (e->button() == Qt::LeftButton) {
        m_checked = !m_checked;
        m_anim->stop();
        m_anim->setStartValue(m_t);
        m_anim->setEndValue(m_checked ? 1.0 : 0.0);
        m_anim->start();
        emit toggled(m_checked);
        update();
    }
}

void ToggleSwitch::keyPressEvent(QKeyEvent* e) {
    if (e->key() == Qt::Key_Space || e->key() == Qt::Key_Return || e->key() == Qt::Key_Enter) {
        m_checked = !m_checked;
        m_anim->stop();
        m_anim->setStartValue(m_t);
        m_anim->setEndValue(m_checked ? 1.0 : 0.0);
        m_anim->start();
        emit toggled(m_checked);
        update();
    }
    QWidget::keyPressEvent(e);
}
