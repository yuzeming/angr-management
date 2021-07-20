from typing import List

from PySide2.QtWidgets import QGraphicsSimpleTextItem
from PySide2.QtCore import Qt, QRectF

from ...config import Conf
from .qgraph_object import QCachedGraphicsItem


class QUnknownBlock(QCachedGraphicsItem):

    LINEAR_INSTRUCTION_OFFSET = 120
    DEFAULT_TEXT = 'Unknown'

    def __init__(self, workspace, addr, bytes_, parent=None):
        super().__init__(parent=parent)

        self.workspace = workspace
        self.addr = addr
        self.bytes = bytes_

        self._width = 0
        self._height = 0

        self._addr_text = None
        self._addr_item: QGraphicsSimpleTextItem = None
        self._byte_lines: List[QGraphicsSimpleTextItem] = None

        self._config = Conf

        self._init_widgets()

    #
    # Public methods
    #

    def paint(self, painter, option, widget): #pylint: disable=unused-argument

        # painter.setRenderHints(
        #         QPainter.Antialiasing | QPainter.SmoothPixmapTransform | QPainter.HighQualityAntialiasing)
        # painter.setFont(self._config.disasm_font)
        pass

    def _boundingRect(self):
        return QRectF(0, 0, self._width, self._height)

    #
    # Private methods
    #

    def _init_widgets(self):
        # Address
        self._addr_text = "%08x" % self.addr
        self._addr_item = QGraphicsSimpleTextItem(self._addr_text, self)
        self._addr_item.setBrush(Qt.black)
        self._addr_item.setFont(Conf.disasm_font)

        # Bytes
        self._byte_lines = [ ]
        if self.bytes:
            line = ""
            for i, b in enumerate(self.bytes):
                line += "%02x " % b
                if i > 0 and (i + 1) % 16 == 0:
                    self._byte_lines.append(line)
                    line = ""

            if line:
                o = QGraphicsSimpleTextItem(line, self)
                o.setFont(Conf.disasm_font)
                o.setBrush(Qt.black)
                self._byte_lines.append(o)

        else:
            o = QGraphicsSimpleTextItem(QUnknownBlock.DEFAULT_TEXT, self)
            o.setBrush(Qt.black)
            o.setFont(Conf.disasm_font)
            self._byte_lines.append(o)

        self._layout_items_and_update_size()

    def _layout_items_and_update_size(self):

        x, y = 0, 0

        # address
        self._addr_item.setPos(x, y)

        x += self._addr_item.boundingRect().width()
        x += self.LINEAR_INSTRUCTION_OFFSET

        # lines
        max_x = x
        for line in self._byte_lines:
            line.setPos(x, y)
            y += line.boundingRect().height()
            max_x = max(max_x, line.boundingRect().width())

        self._width = max_x
        self._height = y

        self.recalculate_size()
