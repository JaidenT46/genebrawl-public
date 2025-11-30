import {Resources} from "../../gene/Resources";
import {Libc} from "../../libs/Libc";
import {Libg} from "../../libs/Libg";
import {ResourceManager} from "../ResourceManager";
import {MovieClip} from "./MovieClip";
import {Sprite} from "./Sprite";

const DownloadedImage_DownloadedImage = new NativeFunction(
    Libg.offset(0x4B6E94, 0xA4344), 'void', [ 'pointer', 'pointer', 'pointer', 'bool', 'int', 'int', 'int' ] // "DownloadedImage from Chronos must have a folder type"
)

const DownloadedImage_createFromLocalFile = new NativeFunction( // in DownloadedImage ctor, return function in if ( v18 >= 0xFFFFFFFFFFFFFFF0LL ) check
    Libg.offset(0x4B71FC, 0xA4248), 'void', [ 'pointer', 'pointer', 'pointer' ]
) 

export class DownloadedImage extends Sprite { // Please load image перед использованием этого говна
    movieClip: MovieClip;
    
    constructor(path: string) {
        const instance = Libc.malloc(168);

        const mc = ResourceManager.getMovieClip(Resources.UI, "popup_promo");
        const t = mc.getChildByName("img_area");

        DownloadedImage_DownloadedImage(instance, path.scptr(), t.instance, 0, 0, 0, 0);
        DownloadedImage_createFromLocalFile(instance, path.scptr(), t.instance);

        super(instance);

        mc.addChild(instance);

        this.movieClip = mc

    }
}
