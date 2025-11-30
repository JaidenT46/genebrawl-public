import {Libc} from "../../../libs/Libc";
import {Libg} from "../../../libs/Libg";
import {ResourceManager} from "../../ResourceManager";
import {MovieClip} from "../MovieClip";
import {Sprite} from "../Sprite";
import {GameButton} from "./GameButton";

const allocSize = 250;

const movieClipOffset = 112;

const GUIContainer_ctor = new NativeFunction( // "buttons_yoozoo" (DropGUIContainer ctor)
    Libg.offset(0x4C0928, 0xAA0D4), 'void', ['pointer', 'pointer']
);

const GUIContainer_setText = new NativeFunction( // "TID_CONFIRM_GEAR_DIRECT_PURCHASE_TITLE"
    Libg.offset(0xA81EBC, 0x9DB94C), 'void', ['pointer', 'pointer', 'pointer']
);

const GUIContainer_setMovieClip = new NativeFunction(
    Libg.offset(0xA81B58, 0x9DB624), 'void', ['pointer', 'pointer'] // in GUIContainer_ctor 3rd line from bottom
);

const DropGUIContainer_addGameButton = new NativeFunction( // "bcheck"
    Libg.offset(0x4C0BC8, 0xAA3D4), 'pointer', ['pointer', 'pointer', 'bool']
);

const GUIContainer_getMovieClipByName = new NativeFunction(
    Libg.offset(0xA4F1A8, 0x9AC57C), 'pointer', ['pointer', 'pointer']
);

export class DropGUIContainer extends Sprite {
    protected movieClip!: MovieClip;

    constructor(scName: string | NativePointer, exportName?: string) {
        if (exportName) {
            scName = scName as string;

            let instance = Libc.malloc(allocSize);

            GUIContainer_ctor(instance, ResourceManager.getMovieClip(scName, exportName).instance);

            super(instance);
        }
        else {
            super(scName as NativePointer);
        }

        if (!this.instance.add(movieClipOffset).readPointer().isNull()) {
            this.movieClip = new MovieClip(
                this.instance.add(movieClipOffset).readPointer()
            );
        }
        else if (exportName) {
            scName = scName as string;
            this.movieClip = ResourceManager.getMovieClip(scName, exportName);
        }
    }

    getMovieClip(): MovieClip {
        if (!this.movieClip) {
            this.movieClip = new MovieClip(
                this.instance.add(movieClipOffset).readPointer()
            );
        }

        return this.movieClip;
    }

    static getMovieClip(instance: NativePointer): MovieClip {
        return new MovieClip(
            instance.add(movieClipOffset).readPointer()
        );
    }

    setTitle(txt: string) {
        this.setText("title", txt);
    }

    setText(field: string, txt: string) {
        GUIContainer_setText(this.instance, field.ptr(), txt.scptr());
    }

    setMovieClip(movieClip: MovieClip) {
        GUIContainer_setMovieClip(this.instance, movieClip.instance);
    }

    getMovieClipByName(name: string) {
        return new MovieClip(
            GUIContainer_getMovieClipByName(this.instance, name.ptr())
        );
    }

    addGameButton(name: string, bool: boolean) {
        return new GameButton(
            DropGUIContainer_addGameButton(this.instance, name.ptr(), Number(bool))
        );
    }
}
