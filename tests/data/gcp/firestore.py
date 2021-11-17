FIRESTORE_DATABASES = [
    {
        'name': 'firestoredatabase123',
        'locationId': 'location123',
        'type': 'FIRESTORE_NATIVE',
        'concurrencyMode': 'OPTIMISTIC'
    },
    {
        'name': 'firestoredatabase456',
        'locationId': 'location456',
        'type': 'FIRESTORE_NATIVE',
        'concurrencyMode': 'OPTIMISTIC'
    },
]


FIRESTORE_INDEXES = [
    {
        'name': 'index123',
        'queryScope': 'COLLECTION_GROUP',
        'state': 'READY',
        'composite_index_id': 'abcdefg123'
    },
    {
        'name': 'index456',
        'queryScope': 'COLLECTION_GROUP',
        'state': 'READY',
        'composite_index_id': 'abcdefg456'
    },
]
