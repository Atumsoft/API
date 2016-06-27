"""
Generic implementation of tunTap base. Import this for a platform independent experience
"""
import AtumsoftGeneric


# TODO: add required properties here


class AtumsoftManager(AtumsoftGeneric.AtumsoftGeneric):
    def __init__(self, isVirtual=True, isHost=False):
        super(AtumsoftManager, self).__init__(isVirtual)


class AdapterDict(dict):
    def __init__(self, *args, **kwargs):
        super(AdapterDict, self).__init__(*args, **kwargs)