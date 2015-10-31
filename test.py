def dashboard():

    p1 = get_priority_tickets_by_month(1)
    p2 = get_priority_tickets_by_month(2)
    p3 = get_priority_tickets_by_month(3)
    p4 = get_priority_tickets_by_month(4)

    for d in p1:
        label = d['label']
        found = False
        for di in p2:
            if di['label'] == label:
                found = True
        if not found:
            p2.append({'y': 0, 'label': label})

    for d in p1:
        label = d['label']
        found = False
        for di in p3:
            if di['label'] == label:
                found = True
        if not found:
            p3.append({'y': 0, 'label': label})

    for d in p1:
        label = d['label']
        found = False
        for di in p4:
            if di['label'] == label:
                found = True
        if not found:
            p4.append({'y': 0, 'label': label})

    pri1 = sorted(p1, key=lambda k: k['label'])
    pri2 = sorted(p2, key=lambda k: k['label'])
    pri3 = sorted(p3, key=lambda k: k['label'])
    pri4 = sorted(p4, key=lambda k: k['label'])
