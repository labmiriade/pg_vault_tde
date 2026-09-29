void
swap(Relation rel, TableScanDesc scan)
{
    // ruleid: tde-rd-tableam
    const TableAmRoutine **rdam = (const TableAmRoutine **) (void *) &rel->rd_tableam;
    // ruleid: tde-rd-tableam
    rel->rd_tableam = GetHeapamTableAmRoutine();
    // ruleid: tde-rd-tableam
    rdam = (const TableAmRoutine **) (void *) &scan->rs_rd->rd_tableam;
    // ok: tde-rd-tableam
    if (rel->rd_tableam == GetHeapamTableAmRoutine())
        return;
    // ok: tde-rd-tableam
    scan = heap_beginscan(rel, snapshot, 0, NULL, NULL, 0);
}
