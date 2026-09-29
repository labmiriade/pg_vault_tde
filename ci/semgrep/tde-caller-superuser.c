void
check(void)
{
    // ruleid: tde-caller-superuser
    if (!superuser())
        elog(ERROR, "no");
    // ok: tde-caller-superuser
    if (!tde_caller_is_superuser())
        elog(ERROR, "no");
    // ok: tde-caller-superuser
    if (!superuser_arg(GetOuterUserId()))
        elog(ERROR, "no");
}
