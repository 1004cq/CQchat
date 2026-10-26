import UIKit

enum ImageCompressor {
    static func compress(_ image: UIImage) -> (full: Data, thumb: Data)? {
        let fullImage = resize(image, maxEdge: CQ.imageMaxEdge)
        guard let full = fullImage.jpegData(compressionQuality: CQ.imageJpegQuality) else { return nil }
        let thumbImage = resize(image, maxEdge: 160)
        let thumb = thumbImage.jpegData(compressionQuality: 0.6) ?? Data()
        return (full, thumb)
    }

    private static func resize(_ image: UIImage, maxEdge: CGFloat) -> UIImage {
        let size = image.size
        let longest = max(size.width, size.height)
        guard longest > maxEdge else { return image }
        let scale = maxEdge / longest
        let newSize = CGSize(width: size.width * scale, height: size.height * scale)
        let renderer = UIGraphicsImageRenderer(size: newSize)
        return renderer.image { _ in image.draw(in: CGRect(origin: .zero, size: newSize)) }
    }
}
