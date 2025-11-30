import {Libc} from "../../libs/Libc";
import {Libg} from "../../libs/Libg";
import {DisplayObject} from "./DisplayObject";
import {Sprite} from "./Sprite";

const dragHandlerOffset = 192;
const dragHandlerAlignmentOffset = 392;
const dragHandlerPinchingOffset = 398;
const unknownOffset = 664;

const updateVtableOffset = 43 * Process.pointerSize;

const ScrollArea_ctor = new NativeFunction( // friends_info_kr
    Libg.offset(0xA826F8, 0x9DC588), 'void', ['pointer', 'float', 'float', 'int']
);

const ScrollArea_enableHorizontalDrag = new NativeFunction(
    Libg.offset(0xA83408, 0x9DCFE8), 'void', ['pointer' ,'bool']
);

const ScrollArea_enableVerticalDrag = new NativeFunction(
    Libg.offset(0xA833FC, 0x9DCFDC), 'void', ['pointer', 'bool']
);

const ScrollArea_removeAllContent = new NativeFunction( // "emote_config_item"
    Libg.offset(0xA82E70, 0x9DCA58), 'void', ['pointer']
);

const ScrollArea_addContent = new NativeFunction( // "TID_MAP_EDITOR_MODIFIERS_TITLE" -> MapEditorModifierPopup::addModifierItem
    Libg.offset(0xA82E48, 0x9DCA30), 'void', ['pointer', 'pointer']
);

const ScrollArea_scrollTo = new NativeFunction( // "MovieClipHelper::scrollItemToVisibleArea item not in scroll area content" last func
    Libg.offset(0xA8341C, 0x9DCFFC), 'void', ['pointer', 'float', 'float', 'float', 'float']
);

const ScrollArea_updateBounds = new NativeFunction(
    Libg.offset(0xA82C44, 0x9DC828), 'void', [ 'pointer' ]
)

const ScrollArea_addContentDontUpdateBounds = new NativeFunction( // eh? A14E5C
    Libg.offset(0xA838F4, 0x9DD490), 'void', [ 'pointer', 'pointer' ]
)

export class ScrollArea extends Sprite {
    private readonly updateFunc: NativeFunction<void, [NativePointerValue, number]>;

    constructor(width: number, height: number, unk: number) {
        let instance = Libc.malloc(800);
        ScrollArea_ctor(instance, width, height, unk);

        super(instance);

        this.updateFunc = new NativeFunction(this.vtable.add(updateVtableOffset).readPointer(), 'void', ['pointer', 'float']);
    }

    addContent(content: DisplayObject | NativePointer) {
        ScrollArea_addContent(this.instance, content instanceof DisplayObject ? content.instance : content);
    }

    addContentDontUpdateBounds(content: DisplayObject | NativePointer) {
        ScrollArea_addContentDontUpdateBounds(this.instance, content instanceof DisplayObject ? content.instance : content)
    }

    setUnk(unk: boolean) {
        this.instance.add(unknownOffset).writeU8(Number(unk));
    }

    enablePinching(pinching: boolean) {
        this.instance.add(dragHandlerOffset).add(dragHandlerPinchingOffset).writeU8(Number(pinching));
    }

    enableHorizontalDrag(value: boolean) {
        ScrollArea_enableHorizontalDrag(this.instance, Number(value));
    }

    enableVerticalDrag(value: boolean) {
        ScrollArea_enableVerticalDrag(this.instance, Number(value));
    }

    setAlignment(alignment: number) {
        this.instance.add(dragHandlerOffset).add(dragHandlerAlignmentOffset).writeInt(alignment);
    }

    scrollTo(a1: number, a2: number, a3: number, a4: number) {
        ScrollArea_scrollTo(this.instance, a1, a2, a3, a4);
    }

    update(deltaTime: number) {
        this.updateFunc(this.instance, deltaTime);
    }

    updateBounds() {
        ScrollArea_updateBounds(this.instance);
    }

    removeAllContent() {
        ScrollArea_removeAllContent(this.instance);
    }
}