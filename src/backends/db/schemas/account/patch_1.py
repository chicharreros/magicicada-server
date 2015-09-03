# Copyright 2008-2015 Canonical
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
# For further info, check  http://launchpad.net/filesync-server

"""Add account_referral_capability table and update capability summ view."""

SQL = [
    """
    CREATE TABLE account_referral_capability (
        id SERIAL PRIMARY KEY,
        referral_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        capability_id INTEGER NOT NULL REFERENCES account_capability(id)
            ON DELETE CASCADE,
        amount BIGINT,
        active_from TIMESTAMP WITHOUT TIME ZONE NOT NULL,
        active_until TIMESTAMP WITHOUT TIME ZONE
    )
    """,
    """
    CREATE INDEX referral_capability_user_idx ON
        account_referral_capability (user_id)
    """,
    """DROP VIEW account_user_capability_summary""",
    """
    CREATE VIEW account_user_capability_summary as
        select up.user_id, up.active_from, up.active_until,
            c.code, pc.base_amount as amount
        from account_user_plan up,
             account_plan p,
             account_plan_capability pc,
             account_capability c
        where up.plan_id = p.id and p.id = pc.plan_id and
            pc.capability_id = c.id and p.is_base_plan is false
        UNION ALL
        select uc.user_id, uc.active_from, uc.active_until,
            c.code, uc.units * c.unit_amount as amount
        from account_user_capability uc,
             account_capability c
        where uc.capability_id=c.id
        UNION ALL
        select u.id as user_id, u.accepted_tos_on as active_from,
            null as active_until, c.code, pc.base_amount as amount
        from account_user_profile u,
             account_plan p,
             account_plan_capability pc,
             account_capability c
        where u.accepted_tos_on is not null and p.id = pc.plan_id and
            pc.capability_id = c.id and p.is_base_plan is true
        UNION ALL
        select rc.user_id, rc.active_from, rc.active_until,
            c.code, rc.amount as amount
        from account_referral_capability rc,
             account_capability c
        where rc.capability_id=c.id
    """,
]


def apply(store):
    """Apply the patch."""
    for sql in SQL:
        store.execute(sql)
