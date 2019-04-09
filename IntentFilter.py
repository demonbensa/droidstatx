class IntentFilter:

    actionList = []
    categoryList = []
    dataList = []

    def __init__(self, name):
        self.name = name
        self.actionList = []
        self.categoryList = []
        self.dataList = []

    def __cmp__(self, other):
        if self.name < other.name:
            return -1
        elif self.name > other.name:
            return 1
        else:
            return 0

    def __repr__(self):
        return "Intent {} [action: {}] [category: {}] [data: {}]".format(
            self.name,
            ", ".join(self.actionList),
            ", ".join(self.categoryList),
            ", ".join(self.dataList))

    def addAction(self, action):
        self.actionList.append(action)

    def addCategory(self, category):
        self.categoryList.append(category)

    def addData(self, data):
        self.dataList.append(data)

    def getActionList(self):
        return self.actionList

    def getCategoryList(self):
        return self.categoryList

    def getDataList(self):
        return self.dataList