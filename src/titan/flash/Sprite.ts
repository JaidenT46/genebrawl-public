import {Libg} from "../../libs/Libg";
import {DisplayObject} from "./DisplayObject";

const Sprite_addChild = new NativeFunction( // "TID_SETTINGS_SCREEN_TITLE"
    Libg.offset(0xA5FD8C, 0x9BCE38), 'void', ['pointer', 'pointer']
);

const Sprite_addChildAt = new NativeFunction( // inside Sprite::addChild
    Libg.offset(0xA5FD94, 0x9BCE40), 'void', ['pointer', 'pointer', 'int']
);

const Sprite_removeChild = new NativeFunction( // "scroll_area_mask"
    Libg.offset(0xA60098, 0x9BD0FC), 'void', ['pointer', 'pointer']
);

const Sprite_removeChildAt = new NativeFunction(
    Libg.offset(0x0, 0x9BD140), 'void', ['pointer', 'int']
);

export class Sprite extends DisplayObject {
    constructor(instance: NativePointer) {
        super(instance);
    }

    addChild(child: NativePointer | DisplayObject): void {
        Sprite_addChild(this.instance, child instanceof NativePointer ? child : child.instance);
    }

    addChildAt(child: NativePointer | DisplayObject, offset: number): void {
        Sprite_addChildAt(this.instance, child instanceof NativePointer ? child : child.instance, offset);
    }

    removeChild(child: NativePointer | DisplayObject) {
        Sprite_removeChild(this.instance, child instanceof NativePointer ? child : child.instance);
    }

    removeChildAt(idx: number): void {
        Sprite_removeChildAt(this.instance, idx);
    }

    static addChild(instance: NativePointer, child: NativePointer | DisplayObject) {
        Sprite_addChild(instance, child instanceof NativePointer ? child : child.instance);
    }

    static addChildAt(instance: NativePointer, child: NativePointer | DisplayObject, offset: number) {
        Sprite_addChildAt(instance, child instanceof NativePointer ? child : child.instance, offset);
    }

    static removeChild(instance: NativePointer, child: NativePointer | DisplayObject) {
        Sprite_removeChild(instance, child instanceof NativePointer ? child : child.instance);
    }

    static removeChildAt(instance: NativePointer, child: NativePointer | DisplayObject, offset: number) {
        Sprite_removeChildAt(instance, offset);
    }
}