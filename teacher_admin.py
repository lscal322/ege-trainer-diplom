"""Administrator-only teacher account and role management."""
import re

import bcrypt
from flask import abort, redirect, render_template, request


def register_teacher_routes(app, get_db, get_cursor, current_user, admin_required):
    @app.route('/py/admin/teachers', methods=['GET', 'POST'])
    @admin_required
    def admin_teachers():
        error = None
        status = 200
        if request.method == 'POST':
            action = request.form.get('action', '')
            email = request.form.get('email', '').strip().lower()
            if action not in ('create', 'grant', 'revoke'):
                abort(400)
            if len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
                error = 'Укажите корректный email.'
            else:
                db = get_db()
                cur = get_cursor()
                try:
                    if action == 'create':
                        name = request.form.get('name', '').strip()
                        password = request.form.get('password', '')
                        if not 2 <= len(name) <= 100:
                            error = 'Имя должно содержать от 2 до 100 символов.'
                        elif len(password) < 8 or len(password.encode()) > 72:
                            error = 'Пароль: минимум 8 символов и максимум 72 байта.'
                        else:
                            password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                            cur.execute(
                                '''INSERT INTO users(name,email,password_hash,is_teacher)
                                   SELECT %s,%s,%s,1
                                   WHERE NOT EXISTS (SELECT 1 FROM users WHERE lower(email)=%s)
                                   ON CONFLICT(email) DO NOTHING''',
                                (name, email, password_hash, email),
                            )
                            if not cur.rowcount:
                                error = 'Этот email уже занят. Для существующего аккаунта используйте выдачу роли.'
                    else:
                        # Conditional write also prevents role changes to admin/disabled accounts.
                        cur.execute(
                            '''UPDATE users SET is_teacher=%s
                               WHERE lower(email)=%s AND disabled=0 AND is_admin=0''',
                            (1 if action == 'grant' else 0, email),
                        )
                        if not cur.rowcount:
                            error = 'Активный пользователь не найден или у него уже есть права администратора.'
                    if error:
                        db.rollback()
                    else:
                        db.commit()
                        return redirect('/py/admin/teachers?success=' + action, code=303)
                except Exception:
                    db.rollback()
                    app.logger.exception('Cannot manage teacher account')
                    error = 'Не удалось сохранить изменения. Попробуйте позже.'
                    status = 503
            if error and status == 200:
                status = 400
        cur = get_cursor()
        cur.execute(
            '''SELECT name,email FROM users
               WHERE is_teacher=1 AND disabled=0 AND is_admin=0 ORDER BY name,email'''
        )
        teachers = cur.fetchall()
        messages = {
            'create': 'Аккаунт учителя создан. Передайте ему email и заданный вами пароль лично.',
            'grant': 'Роль учителя сохранена.',
            'revoke': 'Роль учителя снята. Аккаунт и его результаты сохранены.',
        }
        return render_template(
            'admin_teachers.html', user=current_user(), teachers=teachers, error=error,
            success=messages.get(request.args.get('success')) if request.method == 'GET' else None,
        ), status
