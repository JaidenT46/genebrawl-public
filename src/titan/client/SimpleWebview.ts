import {Libg} from "../../libs/Libg"
import {GenericPopup} from "../flash/gui/GenericPopup"

const SimpleWebview_SimpleWebview = new NativeFunction( // not-so-thicc "popup_news"
    Libg.offset(0x764218, 0x2E3D40), 'pointer', []
);

const SimpleWebview_loadUrl = new NativeFunction(
    Libg.offset(0x7646BC, 0x2E418C), 'void', [ 'pointer', 'pointer' ]
);

export class SimpleWebview {
    instance: NativePointer;

    constructor() {
        this.instance = SimpleWebview_SimpleWebview();
    }

    loadUrl(url: string) {
        SimpleWebview_loadUrl(this.instance, url.scptr());
    }

    setTitle(title: string) {
        GenericPopup.setTitle(this.instance, title);
    }
}