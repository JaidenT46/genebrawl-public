import {GameMain} from "../../laser/client/GameMain";
import {Libc} from "../../libs/Libc";
import {MovieClip} from "../../titan/flash/MovieClip";
import {Stage} from "../../titan/flash/Stage";
import {GeneAssets} from "../GeneAssets";

export class DVD extends MovieClip {
    xSpeed: number = 5;
    ySpeed: number = 5;
    width: number;
    height: number;
    scale: number = 0;
    createdOnStage: boolean = false;

    constructor() {
        const wheelchair = GeneAssets.getAsset("WHEELCHAIR");

        wheelchair.setWidth(100);
        wheelchair.setHeight(100);

        super(wheelchair.instance);

        this.setXY(this.x, this.y);
        this.playOnce();
        this.width = this.getWidth();
        this.height = this.getHeight();
        this.scale = 1;
    }

    update() {
        this.x += this.xSpeed;
        this.y += this.ySpeed;

        this.checkHitBox();
    }

    checkHitBox() {
        if (this.x + this.width * this.scale >= Stage.getX() * 2 || this.x < 0) {
            this.xSpeed *= -1;
        }

        if (this.y + this.height * this.scale >= Stage.getY() * 2 || this.y < 0) {
            this.ySpeed *= -1;
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