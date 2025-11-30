import {GameMain} from "../../laser/client/GameMain";
import {Libc} from "../../libs/Libc";
import {MovieClip} from "../../titan/flash/MovieClip";
import {Stage} from "../../titan/flash/Stage";
import {GeneAssets} from "../GeneAssets";

export class Verevka extends MovieClip {
    createdOnStage: boolean = false;

    constructor() {
        const wheelchair = GeneAssets.getAsset("VEREVKA");

        wheelchair.setWidth(100);
        wheelchair.setHeight(100);

        super(wheelchair.instance);

        this.x = Stage.getX();
        this.y = -1000;

        this.setScale(300);
        this.playOnce();
    }

    update() {
        if (!this.createdOnStage) return;

        if (this.y < 120) {
            this.y += 5;
        }
    }

    createOnStage() {
        if (this.createdOnStage) return;
        this.createdOnStage = true;

        GameMain.getHomeSprite().addChild(this.instance);
    }

    destruct() {
        this.createdOnStage = false;

        GameMain.getHomeSprite().removeChild(this.instance);
        Libc.free(this.instance);
    }
}