import Hls from '../../../src/hls';
import CapLevelController from '../../../src/controller/cap-level-controller';

const levels = [
  {
    width: 360,
    height: 360,
    bandwidth: 1000
  },
  {
    width: 540,
    height: 540,
    bandwidth: 2000
  },
  {
    width: 540,
    height: 540,
    bandwidth: 3000
  },
  {
    width: 720,
    height: 720,
    bandwidth: 4000
  }
];

describe('CapLevelController', function () {
  describe('getMaxLevelByMediaSize', function () {
    it('Should choose the level whose dimensions are >= the media dimensions', function () {
      const expected = 0;
      const actual = CapLevelController.getMaxLevelByMediaSize(levels, 300, 300);
      expect(expected).to.equal(actual);
    });

    it('Should choose the level whose bandwidth is greater if level dimensions are equal', function () {
      const expected = 2;
      const actual = CapLevelController.getMaxLevelByMediaSize(levels, 500, 500);
      expect(expected).to.equal(actual);
    });

    it('Should choose the highest level if the media is greater than every level', function () {
      const expected = 3;
      const actual = CapLevelController.getMaxLevelByMediaSize(levels, 5000, 5000);
      expect(expected).to.equal(actual);
    });

    it('Should return -1 if there levels is empty', function () {
      const expected = -1;
      const actual = CapLevelController.getMaxLevelByMediaSize([], 5000, 5000);
      expect(expected).to.equal(actual);
    });

    it('Should return -1 if there levels is undefined', function () {
      const expected = -1;
      const actual = CapLevelController.getMaxLevelByMediaSize(undefined, 5000, 5000);
      expect(expected).to.equal(actual);
    });
  });

  describe('initialization', function () {
    let capLevelController;
    let firstLevelSpy;
    let startCappingSpy;
    beforeEach(function () {
      const hls = new Hls({ capLevelToPlayerSize: true });
      firstLevelSpy = sinon.spy(hls, 'firstLevel', ['set']);
      capLevelController = new CapLevelController(hls);
      startCappingSpy = sinon.spy(capLevelController, '_startCapping');
    });

    describe('start and stop', function () {
      it('immediately caps and sets a timer for monitoring size size', function () {
        const detectPlayerSizeSpy = sinon.spy(capLevelController, 'detectPlayerSize');
        capLevelController._startCapping();

        expect(capLevelController.timer).to.exist;
        expect(firstLevelSpy.set.calledOnce).to.be.true;
        expect(detectPlayerSizeSpy.calledOnce).to.be.true;
      });

      it('stops the capping timer and resets capping', function () {
        capLevelController.autoLevelCapping = 4;
        capLevelController.timer = 1;
        capLevelController._stopCapping();

        expect(capLevelController.autoLevelCapping).to.equal(Number.POSITIVE_INFINITY);
        expect(capLevelController.restrictedLevels).to.be.empty;
        expect(capLevelController.firstLevel).to.not.exist;
        expect(capLevelController.timer).to.not.exist;
      });
    });

    it('constructs with no restrictions', function () {
      expect(capLevelController.levels).to.be.empty;
      expect(capLevelController.restrictedLevels).to.be.empty;
      expect(capLevelController.timer).to.not.exist;
      expect(capLevelController.autoLevelCapping).to.equal(Number.POSITIVE_INFINITY);

      expect(firstLevelSpy.set.notCalled).to.be.true;
    });

    it('starts capping on BUFFER_CODECS only if video is found', function () {
      capLevelController.onBufferCodecs({ video: {} });
      expect(startCappingSpy.calledOnce).to.be.true;
    });

    it('does not start capping on BUFFER_CODECS if video is not found', function () {
      capLevelController.onBufferCodecs({ audio: {} });
      expect(startCappingSpy.notCalled).to.be.true;
    });

    it('starts capping if the video codec was found after the audio codec', function () {
      capLevelController.onBufferCodecs({ audio: {} });
      expect(startCappingSpy.notCalled).to.be.true;

      capLevelController.onBufferCodecs({ video: {} });
      expect(startCappingSpy.calledOnce).to.be.true;
    });

    it('receives level information from the MANIFEST_PARSED event', function () {
      capLevelController.restrictedLevels = [1];
      let data = {
        levels: [{ foo: 'bar' }],
        firstLevel: 0
      };

      capLevelController.onManifestParsed(data);
      expect(capLevelController.levels).to.equal(data.levels);
      expect(capLevelController.firstLevel).to.equal(data.firstLevel);
      expect(capLevelController.restrictedLevels).to.be.empty;
    });

    it('should start capping in MANIFEST_PARSED if a video codec was signaled', function () {
      capLevelController.onManifestParsed({ video: {} });
      expect(startCappingSpy.calledOnce).to.be.true;
    });

    it('should start capping in MANIFEST_PARSED if a levels and altAudio were signaled', function () {
      capLevelController.onManifestParsed({ levels: [{}], altAudio: true });
      expect(startCappingSpy.calledOnce).to.be.true;
    });
  });
});
