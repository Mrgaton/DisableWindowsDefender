public Vector2 AdjustMouseMovement(Vector2 mouseMovement, float fov, float power)
{
    Vector2 normalizedMovement = new Vector2(mouseMovement.x / Screen.width * 2 - 1, mouseMovement.y / Screen.height * 2 - 1);

    Vector2 adjustedMovement = new Vector2(Mathf.Sign(normalizedMovement.x) * Mathf.Pow(Mathf.Abs(normalizedMovement.x), power), Mathf.Sign(normalizedMovement.y) * Mathf.Pow(Mathf.Abs(normalizedMovement.y), power));

    adjustedMovement *= fov;

    return adjustedMovement;
}
