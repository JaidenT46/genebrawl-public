import {Libg} from "../../libs/Libg";

const DataIcon_setIconClip = new NativeFunction(
    Libg.offset(-1, -1), 'void', ['pointer', 'pointer', 'pointer']
);

export class DataIcon {
    static patch() {
        return; // return if new vulnerability is found
        Interceptor.replace(DataIcon_setIconClip, new NativeCallback((a1, a2, a3) => {
            if (a3.fromsc() === "hero_icon__small") { // fix for vulnerability we found with hedge (related to ranked)
                a2.scptr("sc/emoji.sc");
                a3.scptr("emoji_angry");
            }

            DataIcon_setIconClip(a1, a2, a3);
        }, 'void', ['pointer', 'pointer', 'pointer']));
    }
}